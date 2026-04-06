import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
import argparse
import time
import os
import torch
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Any, Dict
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

app = FastAPI(title="ShieldAI Custom Local OpenAI Gateway")

model = None
tokenizer = None

class Message(BaseModel):
    role: str
    content: str
   
class ChatRequest(BaseModel):
    model: str
    messages: List[Message]
    temperature: Optional[float] = 0.1
    response_format: Optional[Dict[str, Any]] = None

@app.post("/v1/chat/completions")
async def chat_completions(req: ChatRequest):
    global model, tokenizer
    
    messages = [{"role": m.role, "content": m.content} for m in req.messages]
    
    # Sử dụng apply_chat_template tích hợp sẵn của model để bọc System Prompt / User 
    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )
    
    model_inputs = tokenizer([text], return_tensors="pt").to(model.device)
    
    valid_temp = req.temperature if req.temperature and req.temperature > 0 else 0.01
    
    # Xử lý luồng sinh ngôn ngữ qua Neural Network
    with torch.no_grad():
        generated_ids = model.generate(
            **model_inputs,
            max_new_tokens=2048,
            temperature=valid_temp,
            do_sample=True if valid_temp > 0.01 else False,
            pad_token_id=tokenizer.eos_token_id
        )
    
    # Lọc bỏ phần context đầu vào, chỉ lấy response mới được Generate
    generated_ids = [
        output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
    ]
    response_text = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
    
    # Hóa trang kết quả đầu ra thành JSON chuẩn theo tài liệu của OpenAI
    # Điều này đánh lừa các SDKs như `openai` hay `instructor` khiến chúng tiếp nhận chuỗi text bình thường!
    return {
        "id": "chatcmpl-shieldai",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_text
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": len(model_inputs.input_ids[0]),
            "completion_tokens": len(generated_ids[0]),
            "total_tokens": len(model_inputs.input_ids[0]) + len(generated_ids[0])
        }
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShieldAI Custom LLM Server")
    parser.add_argument("--model", type=str, required=True, help="Đường dẫn trỏ vào model weights")
    parser.add_argument("--port", type=int, required=True, help="Cổng chạy server (8000 hoặc 8001)")
    args = parser.parse_args()
    
    print(f"[ShieldAI Engine] Đang làm nóng lò phản ứng Model... (Đường dẫn: {args.model})")
    
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    
    # Chặn đứng lỗi RAM: Nếu tên file là Gemma, dùng BitsAndBytes (4-bit qua LoRA core). Nếu Qwen AWQ, Transformers tự phân giải phần cứng.
    if "Gemma" in args.model:
        print("[ShieldAI Engine] Nhận diện nhân Gemma. Đang kích hoạt lõi ép xung BitsAndBytes 4-bit...")
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.bfloat16
        )
        model = AutoModelForCausalLM.from_pretrained(args.model, quantization_config=bnb_config, device_map="auto")
    else:
        print("[ShieldAI Engine] Nhận diện nhân AWQ (Qwen). Thêm thẳng vào VRAM nguyên khối 4-bit...")
        model = AutoModelForCausalLM.from_pretrained(args.model, device_map="auto")
        
    print(f"[ShieldAI Engine] Nạp đạn VRAM xong! Kích khởi hệ thống càn quét mã độc tại Port {args.port}...")
    
    uvicorn.run(app, host="0.0.0.0", port=args.port)
