import pytest

# Hàm giả lập (Mocking AI Debate)
# Trong môi trường thực, import MultiAgentDebate từ src/multi_agent_extraction.py
def mock_multi_agent_debate(evidence: str):
    """Giả lập 1 vòng đời tranh luận nội bộ của Proxy: (Nhật Ký Debate, Kết Luận, Tổng Số Vòng)"""
    if "192.168.1" in evidence:
         # Localhost: mập mờ, AI tranh biện 2 vòng (Defender thắng cãi Prosecutor) rồi cho ra Benign
         return ["Prosecutor accuses data leak", "Defender clears it"], "Benign (Sạch)", 2
    else:
         # Mã độc rành rành, Judge đâm ngay 1 phát
         return ["Prosecutor: RCE Attack"], "Malicious (Độc)", 1

def test_debate_turn_limits_prevent_infinite_loops():
    """
    KIỂM TRA TIÊU TỐN TÀI NGUYÊN (TOKEN EFFICENCY):
    Một AI Argumentation/Debate Loop quá 3 lần là bị sa lầy (Hallucination Loop). 
    """
    borderline_evidence = "Kết nối tới mạng cục bộ 192.168.1.10"
    
    logs, verdict, turns = mock_multi_agent_debate(borderline_evidence)
    
    # Assert vòng lập tranh biện bắt buộc hội tụ bằng hoặc dưới 3 lần
    assert turns <= 3, f"Quá lãng phí Token: Debate mắc kẹt {turns} vòng do AI không chịu nhường!"
    
    # Assert phán quyết đầu ra luôn thu về 1 trong 2 loại Label chuẩn, không phải text linh tinh
    assert ("Benign" in verdict or "Malicious" in verdict), \
        "Result Verdict bị ảo giác không nằm trong Vocabulary được thiết lập (Benign vs Malicious)."

def test_debate_malicious_strictness():
    evidence = "Gửi /etc/passwd tới server Nga 94.12.33.1 (T1059.004)"
    
    logs, verdict, turns = mock_multi_agent_debate(evidence)
    
    assert turns >= 1, "Thẩm Phán chưa nghe Prosecutor trình bày đã phán (Logic AI bị bỏ qua?)"
    assert "Malicious" in verdict, "Cực kỳ nguy hiểm: Agent Defender (Hàng Rào Bảo Vệ Bào Chữa AI) đã cãi láo mã độc là hàng tốt!"
