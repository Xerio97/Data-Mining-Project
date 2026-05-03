# Safe Multi-Core and Multi-Format Ingestion 
# Ridiculously annoying to debug. Don't touch unless you know
# what you are doing.
load_ember_data <- function(file_paths, max_rows_per_file = 5000) {
  # jsonlite safely parses nested JSON arrays
  library(jsonlite)
  # data.table provides C-level RAM manipulation
  library(data.table)
  # parallel provides multi-core processing for JSONL
  library(parallel)
  # arrow provides Parquet reading
  library(arrow) 
  
  # Detect total system cores and leave exactly 1 core free
  # For my laptop, it's 15, for my PC it's 31
  num_cores <- max(1, detectCores() - 1)
  
  # Initialise an empty list to store the parsed datasets
  dataset_list <- list()
  
  # Iterating over the file_paths argument.
  for (file_path in file_paths) {
    
    # ---------------------------------------------------------
    # ROUTE 1: PARQUET INGESTION (Memory-Safe Path - Still a bit buggy)
    # ---------------------------------------------------------
    if (grepl("\\.parquet$", file_path, ignore.case = TRUE)) {
      message(sprintf("Ingesting %s natively via Apache Arrow (Parquet)...", file_path))
      
      # 1. Open a "lazy" connection to the file in C++. This costs zero RAM.
      ds <- open_dataset(file_path, format = "parquet")
      
      # 2. Pull ONLY the requested number of rows into R's memory
      if (ds$num_rows > max_rows_per_file) {
        # Note: To avoid pulling the whole dataset into RAM, we stream the top N rows 
        # instead of doing a randomised sample.
        # Randomised sample is possible, but it defeats the point
        # by loading the file and shuffling it anyway, killing your RAM
        # My 16GB laptop crashes from it
        dt <- as.data.table(collect(head(ds, max_rows_per_file)))
      } else {
        dt <- as.data.table(collect(ds))
      }
      
    }
    # ---------------------------------------------------------
    # ROUTE 2: JSONL INGESTION (Heavy Processing Path) 
    # This is the recommended route. Works fine on my laptop 
    # ---------------------------------------------------------
    else if (grepl("\\.jsonl$", file_path, ignore.case = TRUE)) {
      message(sprintf("Ingesting %s using a safe %d-core PSOCK cluster...", file_path, num_cores))
      
      con <- file(file_path, "r")
      buffer_limit <- ifelse(is.finite(max_rows_per_file), max_rows_per_file * 1.2, 150000)
      raw_lines <- readLines(con, n = buffer_limit)
      close(con)
      
      raw_lines <- raw_lines[trimws(raw_lines) != ""]
      
      if (length(raw_lines) > max_rows_per_file) {
        raw_lines <- sample(raw_lines, max_rows_per_file)
      }
      
      chunk_size <- ceiling(length(raw_lines) / num_cores)
      line_chunks <- split(raw_lines, ceiling(seq_along(raw_lines) / chunk_size))
      
      cl <- makeCluster(num_cores, type = "PSOCK")
      on.exit(stopCluster(cl), add = TRUE) 
      
      clusterEvalQ(cl, { library(jsonlite); library(data.table) })
      
      parsed_chunks <- parLapply(cl, line_chunks, function(chunk) {
        tryCatch({
          # Micro-Batching to prevent RAM spikes
          micro_chunks <- split(chunk, ceiling(seq_along(chunk) / 250))
          flat_batches <- list()
          
          for (mc in micro_chunks) {
            json_array_string <- paste0("[", paste(mc, collapse = ","), "]")
            df <- jsonlite::fromJSON(json_array_string, simplifyVector = TRUE, flatten = FALSE)
            df_flat <- jsonlite::flatten(df)
            dt_chunk <- as.data.table(df_flat)
            
            # Extract anomalies
            if ("section.sections" %in% names(dt_chunk)) {
              dt_chunk$max_sec_entropy <- sapply(dt_chunk$section.sections, function(sec) {
                if (is.data.frame(sec) && "entropy" %in% names(sec)) return(max(as.numeric(sec$entropy), na.rm=TRUE))
                return(0)
              })
              dt_chunk$max_size_mismatch <- sapply(dt_chunk$section.sections, function(sec) {
                if (is.data.frame(sec) && "vsize" %in% names(sec) && "size" %in% names(sec)) {
                  return(max(abs(as.numeric(sec$vsize) - as.numeric(sec$size)), na.rm=TRUE))
                }
                return(0)
              })
            }
            
            if ("histogram" %in% names(dt_chunk)) {
              dt_chunk$hist_mean <- sapply(dt_chunk$histogram, function(x) if(is.numeric(x)) mean(x, na.rm=TRUE) else 0)
            }
            
            if ("byteentropy" %in% names(dt_chunk)) {
              dt_chunk$ent_max <- sapply(dt_chunk$byteentropy, function(x) if(is.numeric(x)) max(x, na.rm=TRUE) else 0)
            }
            
            # Flatten imports and exports
            collapse_list <- function(x) {
              if (is.list(x)) return(sapply(x, function(vec) paste(as.character(vec), collapse = " ")))
              return(as.character(x))
            }
            
            if ("imports" %in% names(dt_chunk)) dt_chunk[, imports := collapse_list(imports)]
            if ("exports" %in% names(dt_chunk)) dt_chunk[, exports := collapse_list(exports)]
            
            # Brutally destroy ANY remaining nested lists
            bad_cols <- names(dt_chunk)[sapply(dt_chunk, is.list)]
            if (length(bad_cols) > 0) dt_chunk[, (bad_cols) := NULL]
            
            flat_batches[[length(flat_batches) + 1]] <- dt_chunk
            rm(df, df_flat, dt_chunk, json_array_string)
            gc()
          }
          
          return(data.table::rbindlist(flat_batches, fill = TRUE))
          
        }, error = function(e) {
          return(data.table())
        })
      })
      
      stopCluster(cl)
      on.exit() 
      
      dt <- rbindlist(parsed_chunks, fill = TRUE)
      
    } 
    # ---------------------------------------------------------
    # ROUTE 3: UNSUPPORTED FILE
    # Won't happen for our purposes, but useful I guess?
    # ---------------------------------------------------------
    else {
      warning(sprintf("Skipping unsupported file format: %s. Please provide .jsonl or .parquet.", file_path))
      next
    }
    
    # Skip if the table is empty
    if (nrow(dt) == 0) next 
    
    # ---------------------------------------------------------
    # SHARED LOGIC: DUPLICATE HUNTING & TYPE SAFETY
    # My dataset provides no dupes
    # ---------------------------------------------------------
    if ("sha256" %in% names(dt)) {
      initial_rows <- nrow(dt)
      dt <- unique(dt, by = "sha256")
      dupes_found <- initial_rows - nrow(dt)
      if (dupes_found > 0) message(sprintf("   -> Swept and deleted %d duplicate file hashes.", dupes_found))
    }
    
    if ("imports" %in% names(dt)) {
      dt[is.na(imports) | grepl("character.0.", imports), imports := ""] 
    } else {
      dt[, imports := ""]
    }
    
    if ("exports" %in% names(dt)) {
      dt[is.na(exports) | grepl("character.0.", exports), exports := ""]
    } else {
      dt[, exports := ""]
    }
    
    if (!"general.imports" %in% names(dt)) dt[, general.imports := 0]
    if (!"strings.entropy" %in% names(dt)) dt[, strings.entropy := 0]
    
    if ("label" %in% names(dt)) dt <- dt[label %in% c(0, 1)]
    
    # Store the fully cleaned data set into our master list
    dataset_list[[file_path]] <- dt
    
    rm(dt); gc() 
  }
  
  # Bind the lists into one final object and return it
  return(rbindlist(dataset_list, fill = TRUE))
}