# Generate statistical performance metrics and visual confusion matrices for the model

evaluate_model <- function(pipeline_results) {
  library(tidymodels)
  library(xgboost)
  library(ggplot2)
  library(patchwork)
  library(Ckmeans.1d.dp) # Required by XGBoost for clustering the importance plot
  
  message("\n--- TUNED XGBOOST RESULTS ---")
  print(metrics(pipeline_results$xgb, truth = label, estimate = .pred_class))
  
  # 1. The Confusion Matrix 
  conf_matrix <- conf_mat(pipeline_results$xgb, truth = label, estimate = .pred_class)
  # THE FIX: Removed the redundant scale_fill command that caused the warning
  plot_cm <- autoplot(conf_matrix, type = "heatmap") +
    labs(title = "XGBoost Confusion Matrix")
  
  # 2. Feature Importance Plot
  importance_matrix <- xgb.importance(
    feature_names = pipeline_results$feature_names, 
    model = pipeline_results$raw_model
  )
  
  plot_importance <- xgb.ggplot.importance(importance_matrix, top_n = 20, measure = "Gain") +
    theme_minimal() +
    labs(title = "Top 20 Malware Indicators", subtitle = "Measured by Information Gain", x = "Importance", y = "Feature")
  
  return(list(confusion_matrix = plot_cm, feature_importance = plot_importance))
}