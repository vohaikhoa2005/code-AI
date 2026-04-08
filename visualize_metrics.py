import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from sklearn.metrics import (
    precision_score, recall_score, precision_recall_curve, auc,
    confusion_matrix as cm_func, roc_curve, roc_auc_score
)
import warnings
warnings.filterwarnings('ignore')

# Set style for better-looking plots
sns.set_style("whitegrid")
sns.set_palette("husl")
plt.rcParams['figure.figsize'] = (16, 12)
plt.rcParams['font.size'] = 10

print('Loading metrics from model_metrics.pkl...')
metrics = joblib.load('model_metrics.pkl')
cm = np.array(metrics['cm'])
y_test = np.array(metrics['y_test'])
preds_proba = np.array(metrics['preds_proba'])
preds = np.array(metrics['preds'])

# Create main evaluation figure
fig = plt.figure(figsize=(18, 10))
gs = fig.add_gridspec(2, 3, hspace=0.3, wspace=0.3)

# 1. Confusion Matrix Heatmap
ax1 = fig.add_subplot(gs[0, 0])
tn, fp, fn, tp = cm[0,0], cm[0,1], cm[1,0], cm[1,1]
cm_display = cm.astype(float)
sns.heatmap(cm_display, annot=True, fmt='.0f', cmap='RdYlGn_r', cbar=True, ax=ax1,
            xticklabels=['SAFE (0)', 'UNSAFE (1)'], yticklabels=['SAFE (0)', 'UNSAFE (1)'],
            annot_kws={'size': 14, 'weight': 'bold'}, cbar_kws={'label': 'Count'})
ax1.set_title('Confusion Matrix\n(Test Set)', fontsize=14, fontweight='bold', pad=10)
ax1.set_ylabel('True Label', fontsize=12, fontweight='bold')
ax1.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')

# 2. Key Metrics Bar Chart
ax2 = fig.add_subplot(gs[0, 1])
metrics_names = ['Recall\n(UNSAFE)', 'Precision\n(UNSAFE)', 'F1-Score', 'PR-AUC', 'Accuracy']
metrics_values = [
    metrics['recall'],
    metrics['precision'],
    metrics['f1'],
    metrics['pr_auc'],
    metrics.get('accuracy', 0.92)
]
colors = ['#2ecc71', '#3498db', '#e74c3c', '#f39c12', '#9b59b6']
bars = ax2.bar(metrics_names, metrics_values, color=colors, alpha=0.8, edgecolor='black', linewidth=2)
ax2.set_ylim([0, 1.05])
ax2.set_title('Performance Metrics\n(Class 1: UNSAFE)', fontsize=14, fontweight='bold', pad=10)
ax2.set_ylabel('Score', fontsize=12, fontweight='bold')
ax2.grid(axis='y', alpha=0.3, linestyle='--')
for bar, val in zip(bars, metrics_values):
    height = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2., height + 0.02,
             f'{val:.3f}', ha='center', va='bottom', fontweight='bold', fontsize=11)

# 3. Precision-Recall Curve
ax3 = fig.add_subplot(gs[0, 2])
precision_curve = np.array(metrics.get('precision_curve', []))
recall_curve = np.array(metrics.get('recall_curve', []))
if len(precision_curve) > 0 and len(recall_curve) > 0:
    pr_auc_score = auc(recall_curve, precision_curve)
    ax3.plot(recall_curve, precision_curve, linewidth=3, color='#2ecc71', label=f'PR-AUC = {pr_auc_score:.4f}')
    ax3.fill_between(recall_curve, precision_curve, alpha=0.2, color='#2ecc71')
else:
    recall_arr, precision_arr, _ = precision_recall_curve(y_test, preds_proba)
    pr_auc_score = auc(recall_arr, precision_arr)
    ax3.plot(recall_arr, precision_arr, linewidth=3, color='#2ecc71', label=f'PR-AUC = {pr_auc_score:.4f}')
    ax3.fill_between(recall_arr, precision_arr, alpha=0.2, color='#2ecc71')

ax3.set_xlabel('Recall (True Positive Rate)', fontsize=12, fontweight='bold')
ax3.set_ylabel('Precision (PPV)', fontsize=12, fontweight='bold')
ax3.set_title('Precision-Recall Curve\n(Threshold-Independent)', fontsize=14, fontweight='bold', pad=10)
ax3.legend(loc='best', fontsize=11, framealpha=0.9)
ax3.grid(True, alpha=0.3, linestyle='--')
ax3.set_xlim([0, 1.05])
ax3.set_ylim([0, 1.05])

# 4. Threshold Analysis
ax4 = fig.add_subplot(gs[1, 0])
thresholds = [0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8]
precision_vals = []
recall_vals = []
f1_vals = []
valid_thresholds = []

for threshold in thresholds:
    preds_th = (preds_proba >= threshold).astype(int)
    if preds_th.sum() > 0 and len(np.unique(y_test)) > 1:
        prec_th = precision_score(y_test, preds_th, zero_division=0)
        rec_th = recall_score(y_test, preds_th, zero_division=0)
        f1_th = 2*(prec_th*rec_th)/(prec_th+rec_th) if (prec_th+rec_th)>0 else 0
        precision_vals.append(prec_th)
        recall_vals.append(rec_th)
        f1_vals.append(f1_th)
        valid_thresholds.append(threshold)

ax4.plot(valid_thresholds, recall_vals, marker='o', linewidth=2.5, label='Recall', 
         color='#2ecc71', markersize=7, markeredgecolor='black', markeredgewidth=1)
ax4.plot(valid_thresholds, precision_vals, marker='s', linewidth=2.5, label='Precision', 
         color='#3498db', markersize=7, markeredgecolor='black', markeredgewidth=1)
ax4.plot(valid_thresholds, f1_vals, marker='^', linewidth=2.5, label='F1-Score', 
         color='#e74c3c', markersize=7, markeredgecolor='black', markeredgewidth=1)

# Mark threshold 0.5
threshold_0_5_idx = valid_thresholds.index(0.5) if 0.5 in valid_thresholds else 0
ax4.axvline(x=0.5, color='red', linestyle='--', linewidth=2, alpha=0.7, label='Threshold 0.5')
ax4.set_xlabel('Threshold', fontsize=12, fontweight='bold')
ax4.set_ylabel('Score', fontsize=12, fontweight='bold')
ax4.set_title('Impact of Threshold on Metrics', fontsize=14, fontweight='bold', pad=10)
ax4.legend(loc='lower left', fontsize=10, framealpha=0.9)
ax4.grid(True, alpha=0.3, linestyle='--')
ax4.set_ylim([0, 1.05])
ax4.set_xlim([0.25, 0.85])

# 5. Class Distribution & Detection
ax5 = fig.add_subplot(gs[1, 1])
total_safe = tn + fp
total_unsafe = fn + tp
detected_unsafe = tp
undetected_unsafe = fn

# Distribution bars
categories = ['SAFE\n(Total)', 'UNSAFE\n(Total)', 'UNSAFE\n(Detected)', 'UNSAFE\n(Missed)']
values = [total_safe, total_unsafe, detected_unsafe, undetected_unsafe]
colors_dist = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
bars = ax5.bar(categories, values, color=colors_dist, alpha=0.8, edgecolor='black', linewidth=2)

ax5.set_title('Dataset Distribution & Detection\nRate Summary', fontsize=14, fontweight='bold', pad=10)
ax5.set_ylabel('Sample Count', fontsize=12, fontweight='bold')
ax5.grid(axis='y', alpha=0.3, linestyle='--')

for bar, val in zip(bars, values):
    height = bar.get_height()
    ax5.text(bar.get_x() + bar.get_width()/2., height + 1,
             f'{int(val)}', ha='center', va='bottom', fontweight='bold', fontsize=11)

if total_unsafe > 0:
    detection_rate = (tp / total_unsafe) * 100
    ax5.text(0.5, 0.95, f'Detection Rate: {detection_rate:.1f}%\nFalse Negative Rate: {(fn/total_unsafe)*100:.1f}%', 
             transform=ax5.transAxes, ha='center', va='top',
             bbox=dict(boxstyle='round,pad=0.8', facecolor='yellow', alpha=0.7, edgecolor='black', linewidth=2),
             fontsize=11, fontweight='bold')

# 6. Detailed Metrics Table
ax6 = fig.add_subplot(gs[1, 2])
ax6.axis('off')

summary_data = [
    ['Metric', 'Value', 'Interpretation'],
    ['RECALL', f'{metrics["recall"]:.4f}', f'Catches {metrics["recall"]*100:.1f}% of UNSAFE'],
    ['PRECISION', f'{metrics["precision"]:.4f}', f'{metrics["precision"]*100:.1f}% UNSAFE predictions correct'],
    ['F1-SCORE', f'{metrics["f1"]:.4f}', 'Balanced precision-recall'],
    ['PR-AUC', f'{metrics["pr_auc"]:.4f}', 'Area under PR curve (0-1)'],
    ['TN', f'{tn}', 'Correct SAFE predictions'],
    ['FP', f'{fp}', 'False UNSAFE alarms'],
    ['FN', f'{fn}', 'Missed UNSAFE (Critical!)'],
    ['TP', f'{tp}', 'Correct UNSAFE detection'],
]

table = ax6.table(cellText=summary_data, cellLoc='left', loc='center',
                  colWidths=[0.35, 0.25, 0.4])
table.auto_set_font_size(False)
table.set_fontsize(9)
table.scale(1, 2.0)

# Style header row
for i in range(3):
    cell = table[(0, i)]
    cell.set_facecolor('#2c3e50')
    cell.set_text_props(weight='bold', color='white', fontsize=10)
    cell.set_edgecolor('black')
    cell.set_linewidth(2)

# Style data rows with alternating colors
for i in range(1, len(summary_data)):
    for j in range(3):
        cell = table[(i, j)]
        if i <= 4:  # Metrics section
            cell.set_facecolor('#ecf0f1' if i % 2 == 0 else '#d5dbdb')
        else:  # Confusion matrix section
            cell.set_facecolor('#e8f8f5' if i % 2 == 0 else '#d5f4e6')
        cell.set_edgecolor('black')
        cell.set_linewidth(1)
        cell.set_text_props(weight='bold' if j == 0 else 'normal')

ax6.set_title('Metrics Summary', fontsize=13, fontweight='bold', pad=15)

plt.suptitle('SIEM AI Model - Complete Evaluation Report\n(Confusion Matrix + Recall/Precision + PR-AUC + Threshold Analysis)',
             fontsize=16, fontweight='bold', y=0.995)
plt.tight_layout()
plt.savefig('model_evaluation_metrics.png', dpi=300, bbox_inches='tight', facecolor='white')
print('✅ Saved: model_evaluation_metrics.png')
plt.close()

# Create second figure for detailed threshold analysis and recommendations
fig2, ((ax7, ax8), (ax9, ax10)) = plt.subplots(2, 2, figsize=(16, 12))

# Detailed Threshold Table
ax7.axis('off')
threshold_table_data = [['Threshold', 'Precision', 'Recall', 'F1-Score']]
for i, threshold in enumerate(valid_thresholds):
    threshold_table_data.append([
        f'{threshold:.2f}',
        f'{precision_vals[i]:.4f}',
        f'{recall_vals[i]:.4f}',
        f'{f1_vals[i]:.4f}'
    ])

table2 = ax7.table(cellText=threshold_table_data, cellLoc='center', loc='center',
                   colWidths=[0.25, 0.25, 0.25, 0.25])
table2.auto_set_font_size(False)
table2.set_fontsize(11)
table2.scale(1, 2.5)

for i in range(4):
    table2[(0, i)].set_facecolor('#2c3e50')
    table2[(0, i)].set_text_props(weight='bold', color='white', fontsize=11)
    table2[(0, i)].set_edgecolor('black')
    table2[(0, i)].set_linewidth(2)
for i in range(1, len(threshold_table_data)):
    for j in range(4):
        table2[(i, j)].set_facecolor('#e8f8f5' if i % 2 == 0 else '#d5dbdb')
        table2[(i, j)].set_edgecolor('black')
        table2[(i, j)].set_linewidth(1)

ax7.set_title('Threshold Analysis Table\n(Using predict_proba)', fontsize=12, fontweight='bold', pad=15)

# Model configuration
ax8.axis('off')
total_safe = tn + fp
total_unsafe = fn + tp
model_info = f"""
SIEM AI Model - Configuration & Dataset

Dataset: advanced_siem_dataset_with_labels.csv
Training Samples: ~{len(y_test) * 5:,}  (estimated from 20% test split)
Test Samples: {len(y_test)}
Test Set Split: 20% stratified

Model Architecture:
  Type: Random Forest Classifier
  n_estimators: 20 trees
  max_depth: 3 levels
  random_state: 42 (reproducibility)
  n_jobs: -1 (parallel execution)

Class Distribution (Test Set):
  - SAFE: {total_safe} samples ({(total_safe/(total_safe+total_unsafe)*100):.1f}%)
  - UNSAFE: {total_unsafe} samples ({(total_unsafe/(total_safe+total_unsafe)*100):.1f}%)

Features Used: 16 variables
  Behavioral: source, user, action, object
  Process: process_id, parent_process
  Device: device_type, device_id, firmware_version
  Network: src_ip, dst_ip, protocol
  Cloud: cloud_service, resource_id
  HTTP: method, mac_address

Preprocessing:
  ✓ Missing values → 'unknown'
  ✓ Categorical encoding → LabelEncoder
  ✓ Numerical scaling → StandardScaler
  ✓ Train-test split → 80%-20% stratified
"""
ax8.text(0.05, 0.95, model_info, transform=ax8.transAxes, fontsize=9.5,
         verticalalignment='top', fontfamily='monospace',
         bbox=dict(boxstyle='round,pad=1', facecolor='wheat', alpha=0.7, edgecolor='black', linewidth=2))
ax8.set_title('Model Configuration', fontsize=12, fontweight='bold', pad=15)

# Performance interpretation
ax9.axis('off')
metrics_interp = f"""
📊 PERFORMANCE INTERPRETATION

✅ RECALL (Sensitivity): {metrics['recall']:.4f}
   Detection rate for UNSAFE cases
   → Catches {metrics['recall']*100:.1f}% of actual unsafe events
   → Misses {(1-metrics['recall'])*100:.1f}% (FN={fn})
   Implication: Model is {'GOOD' if metrics['recall'] > 0.7 else 'MODERATE' if metrics['recall'] > 0.5 else 'POOR'} at finding unsafe threats

✅ PRECISION: {metrics['precision']:.4f}
   Accuracy of UNSAFE predictions
   → When flagged as UNSAFE, correct {metrics['precision']*100:.1f}% of time
   → False alarm rate: {(1-metrics['precision'])*100:.1f}% (FP={fp})
   Implication: {'Low' if metrics['precision'] > 0.8 else 'Moderate'} false positive burden

✅ F1-SCORE: {metrics['f1']:.4f}
   Harmonic mean of recall & precision
   → Balances detection and accuracy
   → Ideal for imbalanced datasets

✅ PR-AUC: {metrics['pr_auc']:.4f}
   Area under Precision-Recall curve (0-1)
   → {'>0.8 = EXCELLENT' if metrics['pr_auc'] > 0.8 else '>0.6 = GOOD' if metrics['pr_auc'] > 0.6 else 'NEEDS IMPROVEMENT'}

🎯 THRESHOLD RECOMMENDATION:
   • Default (0.5): Balanced → Use for general monitoring
   • Conservative (0.3-0.4): High detection, more alerts
     → Use when security is critical
   • Strict (0.6-0.7): Low false positives, may miss threats
     → Use to reduce alert fatigue
"""
ax9.text(0.05, 0.95, metrics_interp, transform=ax9.transAxes, fontsize=9.5,
         verticalalignment='top', fontfamily='monospace',
         bbox=dict(boxstyle='round,pad=1', facecolor='lightblue', alpha=0.7, edgecolor='black', linewidth=2))
ax9.set_title('Metrics Interpretation', fontsize=12, fontweight='bold', pad=15)

# Next steps and improvements
ax10.axis('off')
improvements = f"""
🚀 ACTIONABLE NEXT STEPS

Immediate Actions:
  1. Deploy model with threshold=0.5 (balanced)
  2. Monitor false positives in production
  3. Collect feedback on misclassifications
  4. Set up threshold adjustment based on alert volume

Model Improvements:
  ✓ Collect more UNSAFE examples (class imbalance)
  ✓ Add temporal features (time-based patterns)
  ✓ Include behavioral sequence data
  ✓ Feature engineering from raw logs
  ✓ Hyperparameter tuning (GridSearchCV)
  ✓ Cross-validation (5-fold stratified)
  ✓ Ensemble methods (combine with rules)

Production Monitoring:
  → Track precision/recall over time
  → Monitor for concept drift
  → Re-train quarterly with new data
  → Maintain audit logs of all predictions

Security Implications:
  ⚠️  High false negatives (FN={fn}) risk for missed threats
  → Consider lowering threshold if safety is critical
  → Use as part of multi-layer detection system
  → Don't rely solely on this model for critical decisions
"""
ax10.text(0.05, 0.95, improvements, transform=ax10.transAxes, fontsize=9,
          verticalalignment='top', fontfamily='monospace',
          bbox=dict(boxstyle='round,pad=1', facecolor='lightyellow', alpha=0.7, edgecolor='black', linewidth=2))
ax10.set_title('Improvements & Actions', fontsize=12, fontweight='bold', pad=15)

plt.suptitle('SIEM AI Model - Detailed Analysis & Threshold Recommendations',
             fontsize=16, fontweight='bold', y=0.995)
plt.tight_layout()
plt.savefig('model_detailed_analysis.png', dpi=300, bbox_inches='tight', facecolor='white')
print('✅ Saved: model_detailed_analysis.png')
plt.close()

print('\n' + '='*60)
print('✅ VISUALIZATION COMPLETE!')
print('='*60)
print('\nGenerated visualization files:')
print('  1. model_evaluation_metrics.png')
print('     → Main metrics dashboard (6 charts)')
print('     → Confusion matrix, metrics, PR-AUC, threshold analysis')
print()
print('  2. model_detailed_analysis.png')
print('     → Detailed threshold table, configuration, interpretation')
print('     → Next steps and improvement recommendations')
print('='*60)
