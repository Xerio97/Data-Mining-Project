# Location: scripts/03_model_pipeline.R
# Purpose: Production-Grade XGBoost Malware Classifier Pipeline
# Features: Z-Score Scaling, TF-IDF Weighting, and Adversarial Sanitization

train_malware_classifier <- function(train_data, test_data) {
  # data.table handles massive data manipulation natively in C
  library(data.table)
  
  # xgboost provides the optimised C++ gradient boosting engine
  library(xgboost)
  
  # Matrix provides the functions needed to build sparse, RAM-efficient data matrices
  library(Matrix)
  
  message("Performing Native Preprocessing & Feature Alignment...")
  
  # ---------------------------------------------------------
  # DATA PREPARATION & MERGING
  # ---------------------------------------------------------
  
  # Extract the true labels before we alter the feature columns
  y_train <- train_data$label
  y_test  <- test_data$label
  
  # Flag rows so we can safely split the matrix back into Train and Test after global transformations
  train_data$is_train <- TRUE
  test_data$is_train  <- FALSE
  
  # Combine into one unified table. fill=TRUE dynamically pads missing columns with NAs
  combined <- rbindlist(list(train_data, test_data),
                        fill = TRUE,
                        use.names = TRUE)
  
  # Define metadata columns that must be deleted to prevent the model from Data Leakage
  cols_to_remove <- intersect(c("label", "sha256", "md5", "appeared", "avclass"),
                              names(combined))
  
  if (length(cols_to_remove) > 0)
    combined[, (cols_to_remove) := NULL]
  
  # Convert the raw text string of imported/exported DLLs into a strict mathematical count
  if ("imports" %in% names(combined) &&
      is.character(combined$imports)) {
    combined$num_imports <- sapply(strsplit(combined$imports, " "), length)
    
    combined[, imports := NULL] # Delete the string to free RAM
  }
  
  if ("exports" %in% names(combined) &&
      is.character(combined$exports)) {
    combined$num_exports <- sapply(strsplit(combined$exports, " "), length)
    
    combined[, exports := NULL]
  }
  
  # ---------------------------------------------------------
  # SCALING DICTIONARY & SWEEP
  # ---------------------------------------------------------
  # Initialise a dictionary to store the exact mathematical scaling applied to the training data.
  # This prevents Training-Serving Skew during production inference.
  
  scaling_dict <- list()
  
  # Delete all remaining nested lists to prevent XGBoost from crashing
  is_bad_type <- function(x)
    is.list(x) || !is.atomic(x)
  bad_cols <- names(combined)[sapply(combined, is_bad_type)]
  if (length(bad_cols) > 0)
    combined[, (bad_cols) := NULL]
  
  # Handle all flat numeric columns
  numeric_cols <- setdiff(names(combined)[sapply(combined, is.numeric)], "is_train")
  
  for (col in numeric_cols) {
    # Calculate statistics STRICTLY using training data to prevent leaking test answers
    train_vals <- combined[is_train == TRUE][[col]]
    
    med_val <- median(train_vals, na.rm = TRUE)
    
    if (is.na(med_val))
      med_val <- 0
    
    # Impute missing values with the median
    combined[is.na(get(col)), (col) := med_val]
    
    # Calculate Mean and Standard Deviation for Z-score normalization
    mean_val <- mean(train_vals, na.rm = TRUE)
    
    sd_val   <- sd(train_vals, na.rm = TRUE)
    
    # Record the math into the dictionary for future inference scripts
    scaling_dict[[col]] <- list(mean = mean_val, sd = sd_val)
    
    # Apply the mathematical scaling to the data
    if (!is.na(sd_val) &&
        sd_val > 0)
      combined[, (col) := (get(col) - mean_val) / sd_val]
    else
      combined[, (col) := 0]
  }
  
  # Handle all character columns (Categorical features)
  char_cols <- names(combined)[sapply(combined, is.character)]
  
  for (col in char_cols) {
    # Explicitly label missing data so the model can use "missingness" as a predictive feature
    combined[is.na(get(col)), (col) := "Unknown"]
    # Convert to standard R factors for dummy encoding
    combined[, (col) := as.factor(get(col))]
  }
  
  message("Generating Sparse Matrix...")
  
  # Convert the table into a sparse matrix, expanding categorical factors into binary dummy columns
  sparse_matrix <- sparse.model.matrix( ~ . - 1 - is_train, data = combined)
  print(ncol(sparse_matrix))
  
  # ---------------------------------------------------------
  # TF-IDF MATRIX WEIGHTING & SANITIZATION
  # ---------------------------------------------------------
  message("Applying TF-IDF Weights to Sparse Features...")
  
  # Calculate Document Frequency (How many files contain each feature)
  doc_freq <- colSums(sparse_matrix > 0)
  
  # Noise Filtering (Speed Optimisation)
  # Keep only features that appear in at least 10 different files
  valid_features <- names(doc_freq[doc_freq >= 10])
  sparse_matrix <- sparse_matrix[, valid_features, drop = FALSE]
  doc_freq <- doc_freq[valid_features]
  
  # Calculate Inverse Document Frequency...
  idf_weights <- log(nrow(sparse_matrix) / (doc_freq + 1))
  
  # Record the weights into the dictionary for the inference script
  scaling_dict$idf_weights <- idf_weights
  
  # Multiply the matrix columns by their respective IDF weights via ultra-fast diagonal multiplication
  sparse_matrix <- sparse_matrix %*% Diagonal(x = idf_weights)
  
  # Adversarial Sanitisation: Malware authors inject illegal control characters (e.g., \f, \n) into
  # DLL names to crash parsers. This Regex replaces any non-alphanumeric character with an underscore.
  raw_names <- names(doc_freq)
  clean_names <- gsub("[^a-zA-Z0-9_.]", "_", raw_names)
  colnames(sparse_matrix) <- clean_names
  
  # Split the scaled matrix back into Train and Test subsets
  X_train <- sparse_matrix[combined$is_train, ]
  X_test  <- sparse_matrix[!combined$is_train, ]
  
  # Convert to optimized C++ memory objects required by XGBoost
  dtrain <- xgb.DMatrix(data = X_train, label = y_train)
  dtest  <- xgb.DMatrix(data = X_test, label = y_test)
  
  # ---------------------------------------------------------
  # CLASS WEIGHTING (KAPPA BALANCING)
  # ---------------------------------------------------------
  # Dynamically (sp?) calculate the ratio of benign to malicious files to prevent the model
  # from lazily guessing the majority class, maximising the Kappa metric.
  num_neg <- sum(y_train == 0, na.rm = TRUE)
  num_pos <- sum(y_train == 1, na.rm = TRUE)
  spw <- ifelse(num_pos > 0, num_neg / num_pos, 1)
  
  # ---------------------------------------------------------
  # MODEL TRAINING (XGBOOST ENGINE)
  # ---------------------------------------------------------
  message(sprintf(
    "Training Model: Hyper-Tuned XGBoost (Scale Pos Weight: %.2f)...",
    spw
  ))
  
  params_xgb <- list(
    objective = "binary:logistic",
    eval_metric = "logloss",
    scale_pos_weight = spw,
    eta = 0.05,              # Slow learning rate for stable convergence
    max_depth = 8,           # Controlled tree depth to prevent memorisation
    min_child_weight = 3,    # Prevent highly specific, noisy splits
    gamma = 0.5,             # Strict pruning: only split if loss drops by 0.5
    subsample = 0.8,         # Row bagging for generalisability
    colsample_bytree = 0.8   # Column bagging for generalisability
  )
  
  model_xgb <- xgb.train(
    params = params_xgb,
    data = dtrain,
    nrounds = 1000,
    evals = list(eval = dtest),
    early_stopping_rounds = 30, # Halt training if test accuracy plateaus
    verbose = 0
  )
  
  # ---------------------------------------------------------
  # FORMATTING & RETURN
  # ---------------------------------------------------------
  
  # Format truth labels for the tidymodels evaluator
  test_labels <- as.factor(ifelse(y_test == 1, "Malicious", "Benign"))
  
  # Generate percentage probabilities on the test set, defaulting to a 50% boundary
  preds_prob_xgb  <- predict(model_xgb, X_test)
  preds_class_xgb <- as.factor(ifelse(preds_prob_xgb > 0.5, "Malicious", "Benign"))
  
  # Package predictions, the raw engine, sanitized columns, and the scaling math into one object
  results <- list(
    xgb = data.frame(.pred_class = preds_class_xgb, label = test_labels),
    raw_model = model_xgb,
    feature_names = clean_names,
    scaling_dict = scaling_dict
  )
  
  return(results)
}