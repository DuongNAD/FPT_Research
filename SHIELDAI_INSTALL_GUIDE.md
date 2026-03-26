# BẢN HƯỚNG DẪN CÀI ĐẶT & SỬ DỤNG SHIELDAI (ZERO-TRUST PIP PROXY)

Tài liệu này hướng dẫn cách cấu hình máy ảo VMWare an ninh (Sandbox) và biến hệ thống của bạn thành rào chắn đánh chặn các thư viện Python (PyPI) có chứa mã độc.

---

## PHẦN 1: CẤU HÌNH MÁY ẢO VÀ PHÒNG THÍ NGHIỆM (SANDBOX)
Hệ thống sử dụng **VMWare Workstation** và **Ubuntu 24.04**.

**Bước 1: Tạo máy ảo Ubuntu**
- Cài đặt một máy ảo Ubuntu có tài khoản tên là `sandbox` và mật khẩu là `123456`.
- Bật máy ảo lên và đăng nhập vào màn hình chính của hệ điều hành.

**Bước 2: Cài đặt công cụ giám sát mã độc (Bên trong máy ảo)**
Mở Terminal của Ubuntu và gõ dán thẳng dòng lệnh sau:
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv strace tcpdump open-vm-tools open-vm-tools-desktop
```

**Bước 3: Mở đường kết nối cho VIX API**
Kích hoạt tự động chạy VMWare Tools:
```bash
sudo systemctl enable --now open-vm-tools
sudo systemctl status open-vm-tools   # Đảm bảo hiển thị "active (running)"
```

**Bước 4: Cấp quyền Bypass Mật Khẩu cho System Call**
Cho phép hệ thống bên ngoài gọi lệnh ngầm không cần cậy mật khẩu:
```bash
echo "sandbox ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/sandbox
```

**Bước 5: Lưu lại Snapshot thời gian thực (CỰC KỲ QUAN TRỌNG)**
- Hãy đảm bảo máy ảo **VẪN ĐANG BẬT VÀ SÁNG MÀN HÌNH CHÍNH**.
- Trên thanh menu của VMWare, chọn `VM > Snapshot > Take Snapshot`.
- Đặt tên chính xác là: **`CleanState`** (Chữ C và chữ S viết hoa).
- (Nếu phần mềm báo trùng tên thì cứ lưu đè lên, hoặc vào Snapshot Manager xóa sạch cái cũ rồi tạo lại đúng một cái tên duy nhất `CleanState`).
- Bây giờ bạn có thể thu nhỏ cửa sổ VMWare xuống thanh Taskbar (Không được tắt hoàn toàn).

---

## PHẦN 2: CHẠY HỆ THỐNG MÁY CHỦ BẢO VỆ (SHIELDAI PROXY)

**Bước 1: Tải môi trường trên Windows**
Đảm bảo bạn đã cài các thư viện lõi tại dự án:
```cmd
pip install fastapi uvicorn httpx aiofiles websockets requests
```

**Bước 2: Bật Máy Chủ Trung Tâm**
```cmd
cd E:\project\FPT_Research
py backend_api.py
```
Máy chủ sẽ lắng nghe ở cổng `http://localhost:8000`. Cửa sổ này phải luôn được giữ mở.

**Bước 3: Truy cập Giao Diện Theo Dõi (Dashboard)**
Mở trình duyệt Web của bạn và truy cập:
👉 **[http://localhost:8000/dashboard](http://localhost:8000/dashboard)**
(Giao diện màn hình Hắc Ám chuẩn Premium sẽ xuất hiện).

---

## PHẦN 3: KIỂM THỬ (CÁCH KHÁCH HÀNG SỬ DỤNG)

Bất cứ ai muốn cài một gói thư viện Python an toàn, họ sẽ phải thêm chữ `--index-url http://localhost:8000/simple` vào lệnh. Đồng thời chỉnh cấu hình `--timeout 300` (5 phút) để đợi AI phân tích xong mới cho kết quả.

**Ví dụ, cài thử gói `requests` qua tường lửa ShieldAI:**
```cmd
python -m pip install --index-url http://localhost:8000/simple requests --no-cache-dir --ignore-installed --timeout 300
```

1. Ở màn hình CMD Windows, nó sẽ treo (vì đang đứng đợi máy chủ cho phép).
2. Tự động máy VMWare sẽ **Sáng đèn**, quay về Snapshot sạch.
3. Mã độc sẽ bị ném thẳng vào máy ảo Ubuntu. Hàm `strace` sẽ chụp lại toàn bộ bằng chứng.
4. Bằng chứng được chuyển cho bộ lưu trữ (AI sẽ đọc).
5. Báo cáo phân tích hiện thị lên Dashboard Web của bạn, cuối cùng là trả mã 200 (Thành công) hoặc 403 (Bị Cấm) cho màn hình CMD.

---

## SỬA LỖI NHANH (TROUBLESHOOTING)
- **Lỗi `403 Forbidden` liên tục hiện nhưng không thấy log hiện trên web:** Nghĩa là Máy ảo chưa kết nối được (VMWare Tools chưa chạy). Hãy bật lại Ubuntu, làm lại Bước 3 của Phần 1 và Take Snapshot lại khi nó đang mở.
- **Lỗi `Error: The name does not uniquely identify one snapshot`:** Tức là bạn bấm Take Snapshot nhiều quá dẫn đến trùng tên. Hãy vào Snapshot Manager xóa hết đi và làm một cái duy nhất.
- **Lỗi Pip hiện `ReadTimeout`:** Quên thiết lập cờ `--timeout 300` khi cài đặt trên host. Mặc định pip chỉ chờ 15 giây.
