# Master Execution Script

# ---------------------------------------------------------
# Dependency Management
# ---------------------------------------------------------
message("Checking and installing missing dependencies...")

# Define all required packages 
required_packages <- c(
  "data.table", "jsonlite", "arrow", "xgboost", "Matrix", 
  "tidymodels", "ggplot2", "patchwork", "Ckmeans.1d.dp", 
  "ggthemes", "scales"
)
# Identify which packages are not currently installed
missing_packages <- required_packages[!(required_packages %in% installed.packages()[,"Package"])]

# Install any missing packages automatically
if(length(missing_packages) > 0) {
  message(sprintf("Installing %d missing packages: %s", length(missing_packages), paste(missing_packages, collapse = ", ")))
  
  # Safety fallback: Force pre-compiled binaries for arrow on Linux to prevent lockups
  if ("arrow" %in% missing_packages) {
    Sys.setenv(LIBARROW_MINIMAL = "false")
    install.packages("arrow", repos = "https://packagemanager.posit.co/cran/__linux__/jammy/latest")
    # Remove arrow from the list so it doesn't try to install twice
    missing_packages <- missing_packages[missing_packages != "arrow"] 
  }
  
  # Install the remaining packages using standard CRAN mirrors
  if (length(missing_packages) > 0) {
    install.packages(missing_packages)
  }
}

# Load all required packages quietly into the global environment
invisible(lapply(required_packages, library, character.only = TRUE))

# Explicitly load the base parallel package
library(parallel)

message("All dependencies loaded successfully!")
# Source all modular functions into the global environment so they can be called
source("scripts/01_data_ingestion.R")
source("scripts/02_eda.R")
source("scripts/03_model_pipeline.R")
source("scripts/04_evaluation.R")

# Define the exact file paths pointing to the extracted EMBER JSONL data on your
# drive. Comment in or out the kaggle versions
# test_files  <- c("data/test_features.parquet") 
# train_files <- c("data/train_features.parquet")
 test_files  <- c("data/test_features.jsonl") 
 train_files <- c("data/train_features.jsonl")

# Execute Pipeline
# Print status and begin the memory-safe ingestion, passing the hard-coded massive sample ceilings
message("Starting Data Ingestion...")
train_data <- load_ember_data(train_files, max_rows_per_file = 50000)
test_data  <- load_ember_data(test_files, max_rows_per_file = 10000)

message("Generating Exploratory Data Analysis (EDA)...")
# Generate the violin and box-plots, capturing them in a variable rather than rendering immediately
eda_plot <- generate_eda_plots(train_data)
# Save the plot directly to the drive to prevent crashing RStudio's dumb graphics viewer
ggsave("eda_malware_imports.png", plot = eda_plot, width = 10, height = 6)

# Launch the newly optimised, pure XGBoost mathematical pipeline and capture the prediction results
message("Training XGBoost Classifier...")
pipeline_results <- train_malware_classifier(train_data, test_data)

# Pass the results object to the evaluator, capturing the returned visual heatmap
message("Evaluating Model...")
eval_plots <- evaluate_model(pipeline_results)

# Save both plots
ggsave("confusion_matrix.png", plot = eval_plots$confusion_matrix, width = 8, height = 6)
ggsave("feature_importance.png", plot = eval_plots$feature_importance, width = 10, height = 8)

# ---------------------------------------------------------
# Exporting the Model to Disk
# ---------------------------------------------------------
message("Exporting Model to Disk...")
if (!dir.exists("models")) dir.create("models")

# Fixed extension to .ubj to silence the XGBoost warning
# Don't change or you'll get a nag message
xgb.save(pipeline_results$raw_model, "models/xgboost_malware_classifier.ubj")
saveRDS(pipeline_results$feature_names, "models/xgboost_feature_names.rds")

# NEW: Save the math dictionary
saveRDS(pipeline_results$scaling_dict, "models/xgboost_scaling_dict.rds")

message("Pipeline Complete!")