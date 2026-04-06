import os
import sys
import shutil
import time
import json
from pathlib import Path

# Cắm ép đường dẫn để gọi chung không bị lỗi ModuleNotFound
project_root = Path(os.path.abspath(__file__)).parent.parent.parent
prod_src = project_root / "04_Production" / "src"
sys.path.append(str(prod_src))

import sandbox_runner
import multi_agent_extraction

def main():
    malware_dir = project_root / "data" / "quarantine" / "task_doomsday"
    prod_quarantine = project_root / "04_Production" / "quarantine"
    os.makedirs(prod_quarantine, exist_ok=True)
    
    report_lines = []
    report_lines.append("# Báo Cáo Chấm Điểm Thử Nghiệm Multi-Agent (Auto-Benchmark Mode)")
    report_lines.append(f"> **Thời gian khởi chiếu**: {time.ctime()}\n")
    report_lines.append("## A. Thống Kê Điểm Số & Phán Quyết")
    report_lines.append("| Tên Gói Hệ Thống | Độ Trễ (Xử Lý) | Phán Quyết Của Tòa | Thuật Toán Khớp MITRE | Tóm Tắt Lý Do Bắt Tội |")
    report_lines.append("|---|---|---|---|---|")
    
    malware_files = list(malware_dir.glob("*.tar.gz"))
    if not malware_files:
        print("Không tìm thấy tệp mã độc nào để benchmark.")
        return
        
    print("="*60)
    print(f"BẮT ĐẦU VÒNG LẶP BENCHMARK: THỬ LỬA {len(malware_files)} BOM MÃ ĐỘC")
    print("="*60)
    
    for mw in malware_files:
        filename = mw.name
        package_name = filename.replace(".tar.gz", "")
        
        print(f"\n>> [{package_name}] Đang nạp đạn vào Lồng Kính Sandbox...")
        dest_path = prod_quarantine / filename
        shutil.copy2(mw, dest_path)
        
        # Start Clock
        start_time = time.time()
        
        # 1. Kích hoạt Sandbox
        print(f"[{package_name}] Hành Quyết Sandbox trong Docker. Xin chờ khoảng 120s...")
        log_path = sandbox_runner.run_in_sandbox(filename)
        
        if not log_path or not os.path.exists(log_path):
            print(f"[{package_name}] 🚫 LỖI CẤP ĐỘ NHÂN: Lồng Sandbox sụp đổ hoặc văng Out Of Memory.")
            report_lines.append(f"| `{package_name}` | *Dead* | 🛑 KÊNH CÁCH LY THỦNG | N/A | Sandbox sập hoặc Malware thoát được Container |")
            continue
            
        # 2. Đọc xuất log Syscall
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                log_content = f.read()
        except:
            log_content = ""
            
        print(f"[{package_name}] Kéo chài thành công {len(log_content)} kí tự Syscall. Mở Phiên Tòa Multi-Agent GPUs...")
        try:
            verdict = multi_agent_extraction.run_debate(package_name, log_content)
            end_time = time.time()
            elapsed = round(end_time - start_time, 2)
            
            v = str(verdict.get("verdict", "ERROR")).strip()
            mitre = ", ".join(verdict.get("mitre_tactics", []))
            reason = str(verdict.get("reason", "")).replace("\n", " ").replace("|", "I") # Chống vỡ bảng Markdown
            
            # Tô màu Label
            label_verdict = f"🟢 {v}" if v.upper() == "BENIGN" else (f"🔴 {v}" if v.upper() == "MALICIOUS" else f"🟡 {v}")
            
            report_lines.append(f"| `{package_name}` | `{elapsed}s` | **{label_verdict}** | `{mitre}` | {reason} |")
            print(f"[{package_name}] HOÀN TẤT NHỊP TÌM DIỆT! Kết quả: {v} (Tốc độ: {elapsed}s)")
            
        except Exception as e:
            print(f"[{package_name}] 💥 LỖI KHÔNG NGUYÊN BẢN TỪ TÒA ÁN/API: {e}")
            report_lines.append(f"| `{package_name}` | *Crash* | ⚠️ LỖI API / GPU | N/A | Lỗi không mong muốn: {e} |")
            
        # [QUAN TRỌNG] Nhịp nghỉ 10s cho Rate Limit Gemini được phục hồi
        print("Đang nghỉ ngơi 10s để bơm lại Quota API Google...")
        time.sleep(10)

    # Cuối cùng, tổng hợp ra Report File cho Client
    report_dir = project_root / "05_Reporting"
    os.makedirs(report_dir, exist_ok=True)
    report_file = report_dir / "benchmark_results.md"
    
    # Kẹp thêm các chỉ số độ trễ TB
    report_lines.append("\n## B. Đặc Tả Tình Hình Kịch Bản (Self-Evaluation)")
    report_lines.append("1. **Độ Bền API (Resilience)**: Nếu cả 5 lệnh ra thành công mà không có lỗi 429 Limit, cơ chế xoay vòng Key chống sập lưới hoạt động xuất sắc.")
    report_lines.append("2. **Độ Chính Xác (Accuracy)**: Phải cãi trắng án thành công loại 1 (Telemetry) và Chém Bay Đầu 4 loại cực đoan còn lại.")
    
    with open(report_file, "w", encoding="utf-8") as rf:
        rf.write("\n".join(report_lines))
        
    print("="*60)
    print(f"✅ CUỘC CHIẾN ĐÃ VÃN HỒI. Report được in tại:\n {os.path.abspath(report_file)}")

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8')
    main()
