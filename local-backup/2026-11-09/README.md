# Sao lưu dữ liệu cục bộ ThreatFusion — 2026-11-09

Bản sao lưu này giữ 497 tệp dữ liệu cục bộ (1.102.217.872 byte) trước khi dọn bản trên máy:

- Toàn bộ các tệp chưa được Git theo dõi trong `out/`, gồm database, kết quả chạy, báo cáo và hình ảnh.
- `siem/elastic/.env`, giữ nguyên cấu hình và mật khẩu trong bản mã hoá.
- Mẫu EVTX cục bộ trong `datasets/EVTX_ATTACK_SAMPLES/`.
- Một Git bundle chứa toàn bộ các refs và lịch sử hiện có của repository.

Mã nguồn tại commit `d43ea942fb8ec528a8c3ef68dbbb363c03eebf01` trên nhánh `main`. Bản sao lưu dùng AES-256-GCM; từng phần có SHA-256 trong `backup.json`. Khóa giải mã được lưu riêng, **không có trên GitHub**. Giữ file `ThreatFusion-recovery-key-2026-11-09.json` ở nơi riêng của bạn; không commit nó.

## Khôi phục

Cần Git, Python và gói `cryptography`. Thay đường dẫn đến file khóa bằng vị trí bạn đã giữ nó. Thư mục đích phải chưa tồn tại.

```powershell
git clone --single-branch --branch backup/local-data-2026-11-09 https://github.com/thinhEden/ThreatFusion.git ThreatFusion-backup
python -m pip install -r ThreatFusion-backup/local-backup/2026-11-09/requirements.txt
python ThreatFusion-backup/local-backup/2026-11-09/restore.py --key "D:\NoiLuuKhoa\ThreatFusion-recovery-key-2026-11-09.json" --destination "D:\ThreatFusion-AI"
```

Script kiểm tra tất cả các phần, xác thực bản mã, đối chiếu hash của từng tệp, khôi phục mã nguồn từ Git bundle rồi chép lại dữ liệu cục bộ. Không cần tải lại mã nguồn từ mạng trong bước chạy `restore.py`.

Để chỉ kiểm tra bản sao lưu, chạy cùng lệnh nhưng bỏ `--destination`.

Các thư mục `.venv/`, `dashboard/node_modules/`, `build-libtorch/`, `build-status/` và Python cache không nằm trong bản sao lưu. Tạo lại môi trường và build theo README của dự án. Nguồn gốc và điều kiện sử dụng các bộ dữ liệu vẫn được ghi trong tài liệu và manifest dữ liệu của dự án; bản sao lưu không thay đổi chúng.
