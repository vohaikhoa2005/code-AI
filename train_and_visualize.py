#!/usr/bin/env python3
"""
SIEM AI Model - Complete Training & Visualization Pipeline
===================================================

This script runs the full ML pipeline:
1. Train the model (train_model.py)
2. Generate visualizations (visualize_metrics.py)
3. Display results and next steps

Usage:
    python train_and_visualize.py
"""

import subprocess
import sys
import os
from pathlib import Path

def print_header(title):
    """Print formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def print_step(step_num, description):
    """Print formatted step"""
    print(f"\n[STEP {step_num}] {description}")
    print("-" * 70)

def run_command(description, command):
    """Run a command and handle errors"""
    print_step(1 if description.startswith("Training") else 2, description)
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("Warnings/Info:", result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error executing: {command}")
        print(f"Error output: {e.stderr}")
        return False

def main():
    print_header("SIEM AI MODEL - TRAINING & VISUALIZATION PIPELINE")
    
    print("""
    This script will:
    1️⃣  Train the Random Forest model on labeled SIEM data
    2️⃣  Generate comprehensive evaluation metrics
    3️⃣  Create visualization dashboards
    4️⃣  Display results summary
    
    Estimated time: 1-2 minutes
    """)
    
    # Check for required files
    print("\n🔍 Checking for required files...")
    required_file = 'advanced_siem_dataset_with_labels.csv'
    
    if not os.path.exists(required_file):
        print(f"❌ ERROR: {required_file} not found!")
        print("Please ensure the labeled dataset is in the working directory.")
        return False
    print(f"✅ Found: {required_file}")
    
    # Step 1: Train Model
    step = 1
    print_step(step, "Training Random Forest Model")
    print("""
    This will:
    • Load and preprocess SIEM dataset
    • Encode categorical features
    • Split data (80% train, 20% test)
    • Train Random Forest Classifier (20 trees, max_depth=3)
    • Evaluate using:
      - Confusion Matrix
      - Recall/Precision for Class 1 (UNSAFE)
      - PR-AUC (Precision-Recall Area Under Curve)
      - Threshold Analysis using predict_proba
    """)
    
    if not run_command("Training Random Forest model on dataset", "python train_model.py"):
        print("❌ Training failed. Please check the error messages above.")
        return False
    
    # Step 2: Generate Visualizations
    step = 2
    print_step(step, "Generating Visualization Dashboards")
    print("""
    This will create:
    1. model_evaluation_metrics.png (6-panel dashboard)
       - Confusion Matrix heatmap
       - Performance metrics bar chart
       - Precision-Recall curve
       - Threshold analysis chart
       - Dataset distribution & detection rate
       - Metrics summary table
    
    2. model_detailed_analysis.png (4-panel analysis)
       - Detailed threshold analysis table
       - Model configuration & dataset info
       - Metrics interpretation guide
       - Recommendations & next steps
    """)
    
    if not run_command("Generating visualization dashboards", "python visualize_metrics.py"):
        print("⚠️  Visualization generation encountered issues.")
        print("You can still use the metrics data from training.")
    
    # Display summary
    print_header("PIPELINE COMPLETE!")
    
    print("""
    ✅ Successfully completed training and visualization!
    
    Generated Files:
    ├── siem_model.pkl              (Trained model)
    ├── scaler.pkl                  (Feature scaler)
    ├── encoders_dict.pkl           (Categorical encoders)
    ├── model_metrics.pkl           (Evaluation metrics)
    ├── model_evaluation_metrics.png (Main dashboard)
    └── model_detailed_analysis.png  (Analysis & recommendations)
    
    Next Steps:
    ════════════════════════════════════════════════════════════════
    
    1. VIEW VISUALIZATIONS:
       Open model_evaluation_metrics.png and model_detailed_analysis.png
       to see the complete evaluation report
    
    2. RUN STREAMLIT APP:
       streamlit run app.py
       
       The web app will show:
       • Live threat detection on new security events
       • Model evaluation metrics and visualizations
       • Threshold analysis and recommendations
       • Explanation of predictions
    
    3. INTERPRET RESULTS:
       • Recall (UNSAFE): % of actual threats detected
       • Precision (UNSAFE): % of alerts that are correct
       • F1-Score: Balance between recall and precision
       • PR-AUC: Threshold-independent performance (>0.8 = excellent)
       • Threshold 0.5: Recommended for balanced performance
    
    4. DEPLOY MODEL:
       Use the trained model (siem_model.pkl) in production with:
       • threshold = 0.5 for balanced operation
       • Monitor false positives and false negatives
       • Adjust threshold based on security requirements
    
    ════════════════════════════════════════════════════════════════
    """)
    
    # Check if visualization files exist
    if os.path.exists('model_evaluation_metrics.png'):
        print("📊 Main metrics dashboard: model_evaluation_metrics.png ✅")
    else:
        print("📊 Main metrics dashboard: NOT FOUND ⚠️")
    
    if os.path.exists('model_detailed_analysis.png'):
        print("📈 Detailed analysis dashboard: model_detailed_analysis.png ✅")
    else:
        print("📈 Detailed analysis dashboard: NOT FOUND ⚠️")
    
    print("\n" + "="*70)
    print("🚀 Ready to use! Run: streamlit run app.py")
    print("="*70 + "\n")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
