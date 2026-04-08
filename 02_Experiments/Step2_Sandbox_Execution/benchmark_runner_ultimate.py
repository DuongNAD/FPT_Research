import os
import sys
import time
import shutil
from pathlib import Path

# Thêm đường dẫn đúng để import module code
project_root = Path(os.path.abspath(__file__)).parent.parent.parent
sys.path.insert(0, str(project_root / "04_Production" / "src"))
sys.path.insert(0, str(project_root / "02_Experiments" / "Step2_Sandbox_Execution"))

import local_ai_manager
import multi_agent_extraction

def compute_metrics(tp, tn, fp, fn):
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return accuracy, precision, recall, f1

def main():
    start_global_time = time.time()
    task_dir = project_root / "data" / "quarantine" / "task_ultimate"
    
    if not task_dir.exists():
        print(f"[!] LỖI: Không tìm thấy thư mục kịch bản Ultimate: {task_dir}")
        return
        
    packages = [f for f in os.listdir(task_dir) if f.endswith(".tar.gz")]
    if not packages:
        print("[!] Thư mục trống. Hãy chạy create_ultimate_scenarios.py trước.")
        return
        
    print(f"============================================================")
    print(f"BẮT ĐẦU VÒNG LẶP BENCHMARK ULTIMATE: {len(packages)} KỊCH BẢN")
    print(f"============================================================\n")

    report_lines = [
        "# Báo Cáo Chấm Điểm Thử Nghiệm Multi-Agent (Ultimate Metrics Benchmarking)",
        f"> **Report Time**: {time.ctime()}",
        "",
        "## A. Scoring & Verdict Matrix",
        "| Package Name | True Label | AI Verdict | Match? | Latency | Analytical Reasoning |",
        "|---|---|---|---|---|---|"
    ]

    total_processing_times = []
    
    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for idx, pkg_tar in enumerate(packages):
        package_name = pkg_tar.replace(".tar.gz", "")
        # Ground Truth based on naming convention
        is_true_malicious = "malicious" in package_name.lower()
        true_label = "**🔴 MALICIOUS**" if is_true_malicious else "**🟢 BENIGN**"
        
        print(f"\n[{idx+1}/{len(packages)}] Đang xử lý: {package_name}...")
        
        # 1. Thu thập Log (Giả lập sysdig hoặc Sandbox module thật)
        import sandbox_runner
        import kg_transformer
        
        # Sao chép vào Prod Quarantine để sandbox đọc
        prod_quarantine = project_root / "04_Production" / "quarantine"
        os.makedirs(prod_quarantine, exist_ok=True)
        shutil.copy2(str(task_dir / pkg_tar), prod_quarantine / pkg_tar)
        
        print(f">> 1. Kích hoạt Lồng Kính Sandbox...")
        log_path = sandbox_runner.run_in_sandbox(pkg_tar)
        
        if not log_path or not os.path.exists(log_path):
            print(f"🚫 LỖI CẤP ĐỘ NHÂN: Sandbox sụp đổ.")
            continue
            
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_log = f.read()
            log_content = kg_transformer.transform_to_kg(raw_log)
        except Exception as e:
            print(f"🚫 LỖI I/O: {e}")
            continue

        elapsed_time = 0
        
        # 2. QWEN PROSECUTOR
        qwen_path = os.path.join(project_root, "AI_Models", "Qwen2.5-7B.gguf")
        qwen_proc = local_ai_manager.boot_model(qwen_path, 8000, 8192, "chatml")
        try:
            t0 = time.time()
            prosecutor_case = multi_agent_extraction.run_prosecutor_stage(package_name, log_content)
            elapsed_time += (time.time() - t0)
        finally:
            local_ai_manager.kill_model(qwen_proc)
            
        # 3. GEMMA DEFENDER
        gemma_path = os.path.join(project_root, "AI_Models", "Gemma-2-9B.gguf")
        gemma_proc = local_ai_manager.boot_model(gemma_path, 8001, 8192, "gemma")
        try:
            t0 = time.time()
            defense_case = multi_agent_extraction.run_defender_stage(package_name, log_content, prosecutor_case)
            elapsed_time += (time.time() - t0)
        finally:
            local_ai_manager.kill_model(gemma_proc)
            
        # 4. QWEN REBUTTAL
        qwen_proc2 = local_ai_manager.boot_model(qwen_path, 8000, 8192, "chatml")
        try:
            t0 = time.time()
            rebuttal_case = multi_agent_extraction.run_rebuttal_stage(package_name, log_content, defense_case)
            elapsed_time += (time.time() - t0)
        finally:
            local_ai_manager.kill_model(qwen_proc2)
            
        # 5. GEMMA 26B JUDGE
        llama_path = os.path.join(project_root, "AI_Models", "Gemma-4-26B-A4B.gguf")
        llama_proc = local_ai_manager.boot_model(llama_path, 8002, 8192, "gemma")
        try:
            t0 = time.time()
            final_verdict = multi_agent_extraction.run_judge_stage(package_name, prosecutor_case, defense_case, rebuttal_case)
            elapsed_time += (time.time() - t0)
        finally:
            local_ai_manager.kill_model(llama_proc)
            
        total_processing_times.append(elapsed_time)
        elapsed_str = str(round(elapsed_time, 2))
        
        v = str(final_verdict.get("final_verdict", "ERROR")).strip()
        reason = str(final_verdict.get("analytical_reasoning", "")).replace("\n", " ").replace("|", "I")
        
        import re
        def clean_verdict_ui(raw_verdict):
            clean_text = re.sub(r'[^A-Za-z]', '', str(raw_verdict)).upper().strip()
            if "MALICIOUS" in clean_text: return "**🔴 MALICIOUS**", True
            elif "BENIGN" in clean_text or "INNOCENT" in clean_text: return "**🟢 BENIGN**", False
            return "**🟡 SUSPICIOUS**", False
            
        label_verdict, is_pred_malicious = clean_verdict_ui(v)
        
        # Calculate Metrics Stats
        if is_true_malicious and is_pred_malicious: 
            match_status = "✅ TP"
            tp += 1
        elif not is_true_malicious and not is_pred_malicious:
            match_status = "✅ TN"
            tn += 1
        elif not is_true_malicious and is_pred_malicious:
            match_status = "❌ FP"
            fp += 1
        else:
            match_status = "❌ FN"
            fn += 1
            
        report_lines.append(f"| `{package_name}` | {true_label} | {label_verdict} | **{match_status}** | `{elapsed_str}s` | {reason} |")
        print(f"[✅ Xong {package_name}] Pred: {v} | Đúng/Sai: {match_status} (Tốc độ: {elapsed_str}s)")
        
        report_dir = project_root / "05_Reporting"
        os.makedirs(report_dir, exist_ok=True)
        report_file = report_dir / "benchmark_results_ultimate.md"
        with open(report_file, "w", encoding="utf-8") as rf:
            rf.write("\n".join(report_lines))
            rf.write("\n\n*(Đang chạy... Vui lòng chờ...)*")

    # Final Metrics Generation
    accuracy, precision, recall, f1 = compute_metrics(tp, tn, fp, fn)
    avg_time = round(sum(total_processing_times) / len(total_processing_times), 2) if total_processing_times else 0
    total_time = round(time.time() - start_global_time, 2)
    
    report_lines.append("\\n## B. Machine Learning Evaluation Metrics")
    report_lines.append("| Metric | Value | Ý nghĩa |")
    report_lines.append("|---|---|---|")
    report_lines.append(f"| **Accuracy (Độ chính xác chuẩn)** | `{accuracy*100:.2f}%` | Tỷ lệ nhận diện đúng trên tổng thể. |")
    report_lines.append(f"| **Precision (Độ tin cậy)** | `{precision*100:.2f}%` | Khả năng không bắt oan (Tránh quét sai rác). |")
    report_lines.append(f"| **Recall (Độ phủ)** | `{recall*100:.2f}%` | Khả năng không bỏ lọt tội phạm tàng hình. |")
    report_lines.append(f"| **F1-Score** | `{f1*100:.2f}%` | Mức độ hoàn hảo trung bình điều hòa. |")
    
    report_lines.append(f"\\n**Confusion Matrix**: TP=`{tp}`, TN=`{tn}`, FP=`{fp}`, FN=`{fn}`")
    report_lines.append(f"**Hiệu suất Hệ thống**: Tổng thời gian `{total_time}s`, Tốc độ trung bình `{avg_time}s`/gói.")
    
    with open(report_file, "w", encoding="utf-8") as rf:
        rf.write("\\n".join(report_lines))
        
    print(f"\\n============================================================")
    print(f"🔥 VÒNG QUAY BENCHMARK KẾT THÚC! Accuracy: {accuracy*100:.2f}% | F1: {f1*100:.2f}%")
    print(f"Report lưu tại: {os.path.abspath(report_file)}")

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8')
    main()
