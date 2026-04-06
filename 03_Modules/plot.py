import argparse
import os
import json
import matplotlib
# Tắt hiển thị GUI để script có thể lưu file tự động trên Server
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def main(): 
    
    # Từ điển gốc: AI-Scientist sẽ tự chèn (inject) thêm mã sửa vào từ điển này khi tranh biện xong
    labels = {
        "run_0": "Baseline"
    }
    
    metrics_to_plot = ["Accuracy_%", "F1_Score_%", "False_Positive_Rate_%", "Precision_%", "Recall_Detection_Rate_%"]
    all_results = {}
    
    for run_dir, label in labels.items():
        json_path = os.path.join(run_dir, "final_info.json")
        if os.path.exists(json_path):
            # Error Handling: Tránh việc chương trình bị crash nếu file JSON bị hỏng
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Parse lại format {"Accuracy_%": {"means": 100}} hoặc Format giản lược {"Accuracy_%": 100}
                    all_results[label] = {}
                    for k, v in data.items():
                        if k in metrics_to_plot:
                            try:
                                if isinstance(v, dict) and "means" in v:
                                    all_results[label][k] = float(v["means"])
                                else:
                                    all_results[label][k] = float(v) if isinstance(v, (int, float, str)) else v
                            except (ValueError, TypeError):
                                print(f"⚠️ Cảnh báo: Ký hiệu ảo giác của AI '{v}' trên {k}. Thay thế bằng 0.")
                                all_results[label][k] = 0
            except json.JSONDecodeError:
                print(f"⚠️ Cảnh báo: Tệp {json_path} bị lỗi định dạng (Invalid format).")
            except Exception as e:
                print(f"⚠️ Cảnh báo: Lỗi không xác định khi đọc {json_path}: {e}")
        else:
            print(f"⚠️ Cảnh báo: Tệp {json_path} không tồn tại.")
            
    if not all_results:
        print("⚠️ Không tìm thấy dữ liệu (JSON) trong các thư mục Run để vẽ.")
        return

    # Duyệt qua các chỉ số để tạo biểu đồ thanh ngang đơn giản
    for metric in metrics_to_plot:
        x_labels = list(all_results.keys())
        y_values = [all_results[lbl].get(metric, 0) for lbl in x_labels]
        
        # Nếu mọi giá trị của metric này đều bằng 0, skip
        if sum(y_values) == 0 and "Rate" not in metric:
            continue
            
        plt.figure(figsize=(10, 6))
        
        # Color coding: Baseline xám mờ, Mẫu thử xanh hi vọng
        bar_colors = ['#8892b0' if lbl == "Baseline" else '#64ffda' for lbl in x_labels]
        bars = plt.bar(x_labels, y_values, color=bar_colors)
        
        plt.ylabel(metric.replace("_", " "))
        plt.title(f"So sánh chỉ số {metric.replace('_', ' ')}")
        
        # Căn chỉnh biểu đồ 0-110% nếu là accuracy/rate (Trục Y Động - Auto scale)
        if "%" in metric or "Rate" in metric:
            plt.ylim(0, 110)
        
        # Nhét chữ số cụ thể lên đỉnh cột
        for bar in bars:
            height = bar.get_height()
            # Cải thiện Color Contrast: Đổi sang màu tối để dễ đọc trên nền trắng
            plt.text(bar.get_x() + bar.get_width() / 2., height, f'{height:.1f}', 
                     ha='center', va='bottom', fontsize=11, fontweight='bold', color='#0a192f')
        
        # Thêm lưới nằm ngang
        plt.grid(axis='y', linestyle='--', alpha=0.3)
        plt.tight_layout()
        
        # Lưu file
        filename = f"{metric.replace('%', 'pct').lower()}.png"
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✅ Đã vẽ xong biểu đồ: {filename}")
        
        # Giải phóng bộ nhớ để tránh Memory Leak khi tạo nhiều plot
        plt.close()

if __name__ == "__main__":
    main()