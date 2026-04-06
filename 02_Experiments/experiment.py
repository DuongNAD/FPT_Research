import argparse
import os
import sys
import json
import asyncio

# Thêm đường dẫn gốc để import nếu cần
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import evaluate_shield

def main():
    parser = argparse.ArgumentParser()
    # Tham số bắt buộc từ The AI Scientist
    parser.add_argument("--out_dir", type=str, default="run_0", help="Output directory where AI Scientist collects results")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    
    # Chạy cốt lõi hệ thống đánh giá 
    print(f"Running pipeline to save results in: {args.out_dir}")
    try:
        # File gốc dùng asyncio nên phải gọi thông qua event loop
        results = asyncio.run(evaluate_shield.evaluate_shield_pipeline())
        
        metrics = results.get("Metrics", {})
        
        # Mẫu bọc kết quả: AI Scientist bắt buộc final_info.json chứa nested dictionary "means"
        # VD: {"Accuracy_%": {"means": 100}, "F1_Score_%": {"means": 95}}
        final_info = {}
        for metric_name, value in metrics.items():
            # Thêm Fault Tolerance để xử lý an toàn các giá trị không phải là số
            try:
                final_info[metric_name] = {"means": float(value)}
            except (ValueError, TypeError):
                print(f"⚠️ Cảnh báo: Không thể ép kiểu giá trị '{value}' của chỉ số {metric_name} sang số thực. Đang bỏ qua...", file=sys.stderr)
            
        final_info_path = os.path.join(args.out_dir, "final_info.json")
        with open(final_info_path, "w", encoding="utf-8") as f:
            json.dump(final_info, f, indent=4)
            
        print(f"✅ Báo cáo định dạng chuẩn đã lưu thành công tại: {final_info_path}")
    except Exception as e:
        print(f"❌ Lỗi thảm họa khi chạy evaluate_shield_pipeline: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()