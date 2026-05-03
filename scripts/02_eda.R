# Location: scripts/02_eda.R
# Purpose: High-Fidelity EDA Visualizations
# REALLY NEEDS IMPROVEMENTS BEFORE MONDAY!!!!
# Current EDA is GARB

generate_eda_plots <- function(pe_data) {
  library(ggplot2)
  library(patchwork)
  library(ggthemes)
  library(scales) # Needed for comma formatting on Log axes
  
  # Map 0 to "Benign" and 1 to "Malicious" for the legends
  pe_data$class_label <- factor(pe_data$label, levels = c(0, 1), labels = c("Benign", "Malicious"))
  
  # 1. DENSITY PLOT: Shows the true shape of the entropy data, exposing hidden peaks
  plot_entropy <- ggplot(pe_data, aes(x = strings.entropy, fill = class_label)) +
    geom_density(alpha = 0.6, color = "white") +
    scale_fill_manual(values = c("Benign" = "#2ecc71", "Malicious" = "#e74c3c")) +
    theme_fivethirtyeight() +
    labs(title = "PE Entropy (Strings) Distribution", x = "Entropy", fill = "Class") +
    theme(legend.position = "top", axis.title = element_text())
  
  # 2. LOG10 VIOLIN PLOT: +1 prevents log10(0) crashes. Prevents the visualisation from being stretched
  plot_imports <- ggplot(pe_data, aes(x = class_label, y = general.imports + 1, fill = class_label)) +
    geom_violin(trim = FALSE, alpha = 0.8) +
    scale_y_log10(labels = scales::comma) + 
    scale_fill_manual(values = c("Benign" = "#2ecc71", "Malicious" = "#e74c3c")) +
    theme_fivethirtyeight() +
    labs(title = "Total Imports (Log10 Scale)", y = "Number of Imports", x = "") +
    theme(legend.position = "none", axis.title = element_text())
  
  return(plot_entropy / plot_imports)
}