# Giải Thích Random Forest Trong Dự Án SIEM AI

## 1. Random Forest Hoạt Động Như Thế Nào Trong Bài Toán Phân Loại?

Random Forest là một thuật toán học máy thuộc loại ensemble learning, được sử dụng rộng rãi trong bài toán phân loại (classification). Trong dự án này, Random Forest được triển khai qua thư viện `sklearn.ensemble.RandomForestClassifier` để phân loại các phiên mạng SIEM thành "SAFE" (0) hoặc "UNSAFE" (1).

### Cơ Chế Hoạt Động:
- **Ensemble của Decision Trees**: Random Forest tạo ra một "rừng" gồm nhiều cây quyết định (decision trees) độc lập. Mỗi cây được huấn luyện trên một tập con ngẫu nhiên của dữ liệu huấn luyện (bootstrap sampling) và một tập con ngẫu nhiên của các đặc trưng (features).
- **Quy Trình Phân Loại**:
  1. **Bootstrap Sampling**: Từ tập dữ liệu gốc, tạo ra nhiều tập con bằng cách lấy mẫu có hoàn lại (with replacement).
  2. **Xây Dựng Cây**: Mỗi cây được xây dựng bằng cách chọn ngẫu nhiên một số đặc trưng tại mỗi nút phân chia, giúp tăng đa dạng và giảm overfitting.
  3. **Voting**: Khi dự đoán, mỗi cây đưa ra dự đoán riêng (SAFE hoặc UNSAFE), và kết quả cuối cùng là đa số phiếu (majority vote) từ tất cả các cây.
- **Ưu Điểm Trong Phân Loại SIEM**:
  - Xử lý tốt dữ liệu có nhiều đặc trưng hỗn hợp (numeric và categorical).
  - Kháng nhiễu và outliers tốt hơn so với một cây đơn lẻ.
  - Cung cấp độ quan trọng của đặc trưng (feature importance), giúp hiểu rõ yếu tố ảnh hưởng đến phân loại.

Trong code (`siem_ai_training.py`), mô hình được khởi tạo với `RandomForestClassifier(random_state=42)`, đảm bảo kết quả reproducible. Sau khi huấn luyện trên tập train (80% dữ liệu), mô hình đạt độ chính xác cao trên tập test.

## 2. Bạn Định Nghĩa "Phiên Không An Toàn" Dựa Trên Những Yếu Tố Nào?

Trong dự án, "phiên không an toàn" (UNSAFE, label = 1) được định nghĩa dựa trên việc đếm số lượng điều kiện rủi ro từ các đặc trưng của phiên mạng. Cụ thể, trong code (`siem_ai_training.py`), logic gắn nhãn như sau:

### Các Yếu Tố (Điều Kiện):
- **Severity**: Nếu `severity` là "high" hoặc "critical" (độ nghiêm trọng cao).
- **Alert Type**: Nếu `alert_type` không phải NaN (có cảnh báo cụ thể).
- **Duration**: Nếu `duration > 5000` giây (phiên kết nối quá lâu).
- **Bytes**: Nếu `bytes > 1000000` (lượng dữ liệu truyền tải lớn bất thường).

### Quy Tắc Gắn Nhãn:
- Tính tổng số điều kiện thỏa mãn (unsafe_count).
- Nếu `unsafe_count >= 2` (tối thiểu 2 yếu tố rủi ro), thì phiên được gắn nhãn UNSAFE (1).
- Ngược lại, nếu ít hơn 2, là SAFE (0).

Điều này dựa trên các tiêu chí bảo mật thực tế trong SIEM (như trong file `LABELING_CRITERIA.md`), nơi kết hợp nhiều yếu tố để giảm false positives và đảm bảo phát hiện rủi ro chính xác. Ví dụ:
- Một phiên có severity="high" và duration>5000 sẽ là UNSAFE.
- rrrrrrrrrrrrrrrrrrrrrrrrrrrrr
rrrrrrrrrr/025++++++++++

5
## 3. Làm Sao Để Tránh Overfitting Khi Dùng Random Forest?

Overfitting xảy ra khi mô hình học quá tốt trên dữ liệu huấn luyện nhưng kém trên dữ liệu mới. Random Forest ít overfitting hơn decision tree đơn lẻ nhờ ensemble, nhưng vẫn cần kỹ thuật để tối ưu.

### Các Cách Tránh Overfitting Trong Code Hiện Tại:
- **Tuning Hyperparameters**: Mặc dù code hiện tại dùng default, có thể thêm `GridSearchCV` hoặc `RandomizedSearchCV` để tìm giá trị tối ưu cho:
  - `n_estimators`: Số cây (tăng để ổn định nhưng tránh quá nhiều).
  - `max_depth`: Độ sâu tối đa của cây (giới hạn để tránh học quá chi tiết).
  - `min_samples_split`: Số mẫu tối thiểu để phân chia nút (tăng để tổng quát hóa).
  - `min_samples_leaf`: Số mẫu tối thiểu ở lá (tăng để giảm overfitting).
- **Cross-Validation**: Sử dụng `cross_val_score` để đánh giá trên nhiều fold, đảm bảo mô hình không overfitting trên một split cụ thể.
- **Feature Selection**: Chỉ chọn đặc trưng quan trọng (dựa trên `model.feature_importances_`), loại bỏ noise.
- **Pruning**: Giới hạn độ sâu cây hoặc sử dụng `max_features` để chọn ngẫu nhiên ít đặc trưng hơn.
- **Bootstrap và Randomness**: Random Forest tự nhiên dùng bootstrap, nhưng có thể điều chỉnh `bootstrap=False` nếu cần.

Trong code, có thể mở rộng bằng cách thêm:
```python
from sklearn.model_selection import GridSearchCV
param_grid = {'n_estimators': [100, 200], 'max_depth': [10, 20], 'min_samples_split': [2, 5]}
grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=5)
grid_search.fit(X_train, y_train)
best_model = grid_search.best_estimator_
```
Điều này giúp mô hình tổng quát hóa tốt hơn, đặc biệt với dataset SIEM có thể có imbalance hoặc noise.

## 4. Quá Trình Xây Dựng Hệ Thống AI Phân Loại Phiên

Hệ thống được đề xuất là một hệ thống trí tuệ nhân tạo để phân loại các phiên dựa trên hành vi truy cập. Để xây dựng hệ thống này, trước tiên tôi đã thu thập dữ liệu người dùng thực từ các nguồn uy tín như Kaggle, CIC (Canadian Institute for Cybersecurity), CERT (Computer Emergency Response Team) và UCI (University of California, Irvine). Những nguồn này cung cấp các dataset SIEM chất lượng cao, bao gồm log mạng và sự kiện bảo mật thực tế.

Sau khi thu thập dữ liệu, tôi đã chọn lọc một số trường quan trọng để làm đặc trưng chính cho mô hình, bao gồm Tên người dùng (user), Số byte đã truyền (bytes) và Thời lượng phiên (duration, tính bằng giây). Những trường này được chọn vì chúng phản ánh trực tiếp hành vi truy cập và có thể chỉ ra các dấu hiệu bất thường trong mạng.

Tiếp theo, tôi đã thêm nhãn cho từng trường hợp trong dataset: "an toàn" (SAFE, 0) hoặc "không an toàn" (UNSAFE, 1). Việc gắn nhãn dựa trên các quy tắc bảo mật rõ ràng, chẳng hạn như:
- Nếu thời lượng > 2500 giây và số byte > 500.000 → Nhãn: KHÔNG AN TOÀN.
- Nếu loại sự kiện là "mạng", "quy trình", "truy cập" hoặc "đăng nhập" → Nhãn: KHÔNG AN TOÀN.

Dataset sau đó được chia theo tỷ lệ 80% cho huấn luyện và 20% cho kiểm thử, đảm bảo mô hình được đánh giá trên dữ liệu chưa thấy.

Với dữ liệu đã chuẩn bị, tôi sử dụng nó để xây dựng mô hình học máy. Đầu vào của hệ thống bao gồm thông tin như Tên người dùng, Số byte đã truyền và Thời lượng. Những dữ liệu này được tiền xử lý (như mã hóa categorical, scaling numeric) và đưa vào mô hình Rừng ngẫu nhiên (Random Forest) để phân loại.

Đầu ra của hệ thống là dự đoán cho từng phiên: an toàn hoặc không an toàn. Điều này giúp hệ thống tự động tìm ra các phiên nguy hiểm, hỗ trợ các quyết định về bảo mật, như cảnh báo hoặc chặn truy cập, từ đó nâng cao an ninh mạng một cách hiệu quả.</content>
<parameter name="filePath">d:\Information Technology\Semester6\Teacher_Quang-Computing Research Project\code AI\Random_Forest_Explanation.md