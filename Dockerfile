# Sử dụng image python nhẹ làm nền
FROM python:3.9-slim

# Cài đặt các công cụ giám sát mạng và tiến trình: tcpdump và strace
RUN apt-get update && apt-get install -y \
    tcpdump \
    strace \
    && rm -rf /var/lib/apt/lists/*

# Tạo thư mục làm việc
WORKDIR /app

# Thiết lập điểm vào mặc định là bash để dễ dàng truyền script kích nổ
CMD ["/bin/bash"]
