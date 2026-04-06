import asyncio
import json
import time
import sys
import os
import logging
from typing import List, Dict

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from ingestion import download_and_analyze, pipeline_state

pipeline_state.is_interactive = False

def print_banner(text: str):
    print("\n" + "=" * 60)
    print(f"🛡️  {text.center(54)} 🛡️")
    print("=" * 60)

async def evaluate_shield_pipeline() -> Dict:
    test_cases = [
        {"name": "requests-2.31.0.tar.gz", "url": "mock_url", "is_malware": False},
        {"name": "urllib3-2.0.0.tar.gz", "url": "mock_url", "is_malware": False},
        {"name": "numpy-1.26.0.tar.gz", "url": "mock_url", "is_malware": False},
        {"name": "shieldaidemo-1.0.0.tar.gz", "url": "mock_url", "is_malware": True}
    ]

    tp, tn, fp, fn, errors = 0, 0, 0, 0, 0
    start_time = time.time()
    timeout_seconds = 45 

    print_banner("Bắt đầu Đánh Giá AI Scientist Pipeline")

    for idx, case in enumerate(test_cases, 1):
        pkg_name = case["name"]
        is_malware_actual = case["is_malware"]
        print(f"\n[RUN {idx}/{len(test_cases)}] Phân tích: {pkg_name} (Thực tế chứa Mã độc: {is_malware_actual})")

        try:
            is_safe = await asyncio.wait_for(
                download_and_analyze(case["url"], pkg_name),
                timeout=timeout_seconds
            )

            if is_malware_actual:
                if not is_safe:
                    print("✅ Kết quả đúng: Đã chặn Mã Độc (True Positive)")
                    tp += 1
                else:
                    print("❌ Lỗi nghiêm trọng: Bỏ lọt Mã Độc (False Negative)")
                    fn += 1
            else:
                if is_safe:
                    print("✅ Kết quả đúng: Cho đi qua Gói Sạch (True Negative)")
                    tn += 1
                else:
                    print("❌ Cảnh báo: Chặn nhầm Gói Sạch (False Positive)")
                    fp += 1

        except asyncio.TimeoutError:
            print(f"⚠️ Timeout Error: {pkg_name} chạy quá {timeout_seconds} giây. Cảnh báo Infinite Loop!")
            errors += 1
            if is_malware_actual: 
                fn += 1
            else: 
                fp += 1
        except Exception as e:
            print(f"⚠️ Pipeline Crash với {pkg_name}: {e}")
            errors += 1
            if is_malware_actual: 
                fn += 1
            else: 
                fp += 1

    total_time = time.time() - start_time

    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0 
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0
    accuracy = ((tp + tn) / len(test_cases)) * 100 if len(test_cases) > 0 else 0

    results = {
        "Metrics": {
            "Accuracy_%": round(accuracy, 2),
            "Precision_%": round(precision, 2),
            "Recall_Detection_Rate_%": round(recall, 2),
            "F1_Score_%": round(f1_score, 2),
            "False_Positive_Rate_%": round(fpr, 2)
        },
        "Confusion_Matrix": {
            "True_Positives": tp,
            "True_Negatives": tn,
            "False_Positives": fp,
            "False_Negatives": fn,
            "Execution_Errors": errors
        },
        "Performance": {
            "Execution_Time_sec": round(total_time, 2)
        }
    }

    print_banner("KẾT QUẢ ĐÁNH GIÁ (EVALUATION METRICS)")
    print(json.dumps(results, indent=4))

    with open("ai_scientist_metrics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    return results

if __name__ == "__main__":
    asyncio.run(evaluate_shield_pipeline())