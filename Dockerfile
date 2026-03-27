# Sử dụng image python nhẹ làm nền
FROM python:3.9-slim

# Cài đặt các công cụ giám sát mạng và tiến trình: tcpdump và strace
# Cần libcap2-bin để set quyền cho các công cụ giám sát chạy bằng user phụ
RUN apt-get update && apt-get install -y \
    tcpdump \
    strace \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Cấu hình trao quyền truy cập tài nguyên kernel tối thiểu cho tcpdump và strace
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
# Đôi khi strace đòi hỏi quyền gắn trình gỡ lỗi (ptrace)
RUN setcap cap_sys_ptrace=eip /usr/bin/strace

# Thêm 1 người dùng không có quyền quản trị và chuyển quyền
RUN useradd -m sandboxuser
USER sandboxuser

# Tạo thư mục làm việc
WORKDIR /home/sandboxuser

# Thiết lập điểm vào mặc định là bash để dễ dàng truyền script kích nổ
CMD ["/bin/bash"]
