# Mathematically Synchronized Production Inference

library(xgboost)
library(data.table)
library(Matrix)
library(arrow) # Required for fast Parquet reading

source("scripts/01_data_ingestion.R")

# Added target_hashes parameter to allow specific row inferencing
predict_malware <- function(file_path, target_hashes = NULL) {
  message("Loading XGBoost Model, Features, and Scaling Math...")
  model <- xgb.load("models/xgboost_malware_classifier.ubj")
  expected_cols <- readRDS("models/xgboost_feature_names.rds")
  scaling_dict  <- readRDS("models/xgboost_scaling_dict.rds")
  
  message(sprintf("Ingesting target file: %s", file_path))
  
  # Automatically detect file type and route to the correct parser
  if (grepl("\\.parquet$", file_path, ignore.case = TRUE)) {
    # Read Parquet instantly and convert to data.table
    new_data <- as.data.table(read_parquet(file_path))
  } else if (grepl("\\.jsonl$", file_path, ignore.case = TRUE)) {
    # Fallback to our custom JSONL ingestion script
    new_data <- load_ember_jsonl(c(file_path), max_rows_per_file = 10000)
  } else {
    stop("Unsupported file format. Please provide a .jsonl or .parquet file.")
  }
  
  if (nrow(new_data) == 0) stop("File was empty or corrupted.")
  
  # ROW FILTERING: If the user provided specific hashes, subset the data immediately
  if (!is.null(target_hashes) && "sha256" %in% names(new_data)) {
    new_data <- new_data[sha256 %in% target_hashes]
    if (nrow(new_data) == 0) stop("None of the targeted hashes were found in the file.")
    message(sprintf("Filtered dataset to %d targeted rows.", nrow(new_data)))
  }
  
  report <- data.table(
    sha256 = if("sha256" %in% names(new_data)) new_data$sha256 else paste("Unknown_Hash_", 1:nrow(new_data))
  )
  
  message("Aligning and Mathematically Scaling Matrix...")
  
  is_bad_type <- function(x) is.list(x) || !is.atomic(x)
  bad_cols <- names(new_data)[sapply(new_data, is_bad_type)]
  if (length(bad_cols) > 0) new_data[, (bad_cols) := NULL]
  
  aligned_matrix <- matrix(0, nrow = nrow(new_data), ncol = length(expected_cols))
  colnames(aligned_matrix) <- expected_cols
  
  shared_cols <- intersect(names(new_data), expected_cols)
  for (col in shared_cols) {
    if (is.numeric(new_data[[col]])) aligned_matrix[, col] <- new_data[[col]]
  }
  aligned_matrix[is.na(aligned_matrix)] <- 0
  
  # APPLY THE Z-SCORES
  for (col in expected_cols) {
    if (col %in% names(scaling_dict) && col != "idf_weights") {
      mean_val <- scaling_dict[[col]]$mean
      sd_val <- scaling_dict[[col]]$sd
      if (!is.na(sd_val) && sd_val > 0) {
        aligned_matrix[, col] <- (aligned_matrix[, col] - mean_val) / sd_val
      } else {
        aligned_matrix[, col] <- 0
      }
    }
  }
  
  # APPLY THE TF-IDF WEIGHTS
  sparse_aligned <- as(aligned_matrix, "sparseMatrix")
  sparse_aligned <- sparse_aligned %*% Diagonal(x = scaling_dict$idf_weights)
  colnames(sparse_aligned) <- expected_cols
  
  message("Running inference engine...")
  dtest <- xgb.DMatrix(data = sparse_aligned)
  probs <- predict(model, dtest)
  
  report$malware_probability <- round(probs * 100, 2)
  report$verdict <- ifelse(probs > 0.5, "MALICIOUS", "BENIGN")
  
  message("Inference Complete!")
  return(report)
}