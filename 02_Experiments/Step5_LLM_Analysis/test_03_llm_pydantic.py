import pytest
import asyncio
import json
from pydantic import BaseModel, Field, ValidationError
import sys

# Khai báo Schema Pydantic ngặt nghèo (Strict Validation)
class MitreTechnique(BaseModel):
    id: str = Field(..., description="ID chiến thuật MITRE, vd: T1059.001")
    name: str = Field(..., description="Tên đầy đủ của Tactic/Technique")

class MitreExtractionModel(BaseModel):
    indicator: dict = Field(..., description="Mô tả API call bị hệ thống Sandbox quét")
    behavior: dict = Field(..., description="Diễn giải hành vi sang ngôn ngữ tự nhiên")
    technique: MitreTechnique
    tactic: MitreTechnique

# MOCK TÍNH NĂNG LLM
# Giả sử đây là hàm lấy kết quả Text raw từ Gemini/Qwen2.5
async def mock_llm_analyze_syscall() -> str:
    """Trả về một JSON String ảo từ model LLM"""
    return json.dumps({
        "indicator": {"api": "execve(/bin/sh)", "package_name": "shieldai-test"},
        "behavior": {"name": "Lén lút khởi chạy một Terminal truy cập shell bên trong máy tính"},
        "technique": {"id": "T1059.004", "name": "Ngôn ngữ lệnh (Unix Shell)"},
        "tactic": {"id": "TA0002", "name": "Thực thi mã nhúng (Execution)"}
    })

async def mock_llm_hallucination() -> str:
    """Giả lập ảo giác (Hallucination) từ LLM làm thiếu field 'technique' quan trọng nhất"""
    return json.dumps({
        "indicator": {"api": "connect(...)"},
        "behavior": {"name": "Botnet kết nối máy chủ CC"},
        # Quên mất key technique và tactic!
        "random_field": 123
    })

@pytest.mark.asyncio
async def test_llm_extraction_strict_schema():
    """
    KIỂM TRA CHỐNG ẢO GIÁC JSON (STRICT SCHEMA VALIDATION):
    Truyền dữ liệu từ LLM thẳng vào Pydantic. Nếu nó parse thành Object Python mượt mà,
    có nghĩa Prompt LLM đang hoạt động tuyệt vời.
    """
    # 1. Gọi hàm sinh Test Case sạch
    raw_json_str = await mock_llm_analyze_syscall()
    
    try:
        data_dict = json.loads(raw_json_str)
        # 🛡️ PYDANTIC VERIFICATION THÉP
        model = MitreExtractionModel(**data_dict)
        
        assert model.technique.id.startswith("T"), "ID của technique trong MITRE phải bắt đầu bằng chữ T"
        assert len(model.behavior) > 0, "Behavior Dictionary không được phép để rỗng"
        
    except ValidationError as e:
         pytest.fail(f"[LLM ERROR] Pydantic báo lỗi thiếu Key trong Schema từ Model!: {e}")
    except json.JSONDecodeError:
         pytest.fail("[LLM ERROR] LLM không trả về cú pháp JSON hợp lệ!")

@pytest.mark.asyncio
async def test_llm_hallucination_catch():
    """
    KIỂM TRA BẪY LỖI:
    Cố tình đưa JSON rác hoặc thiếu field, Pydantic phải Catch được ValidationError
    gây FAIL pytest đúng theo kịch bản bảo mật.
    """
    raw_json_str = await mock_llm_hallucination()
    
    with pytest.raises(ValidationError) as excinfo:
         data_dict = json.loads(raw_json_str)
         # Hệ thống sẽ quăng ValidationError vì json này thiếu 'technique'
         MitreExtractionModel(**data_dict)
         
    # Đảm bảo rác LLM bị kẹt lại tại hàng rào Pydantic thay vì dội sâu vào Neo4j DB
    assert "technique" in str(excinfo.value), "Pydantic không bắt đúng lỗi thiếu field technique!"
