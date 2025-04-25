# Tiny Second-hand Shopping Platform

---

## 주요 기능 요약

- 회원가입 / 로그인 (JWT 인증)
- 상품 등록 / 조회 / 상세 보기 / 삭제
- 사용자 간 1:1 채팅
- 가상 포인트 송금
- 사용자 및 상품 신고 기능
- 관리자 전용 신고 조회 및 처리

---

## 보안 고려 사항

- 비밀번호 bcrypt 해시 처리
- JWT 토큰 기반 인증
- ORM 사용으로 SQL Injection 방지
- 인증된 사용자만 주요 기능 접근 가능
- 관리자 API 접근 제한 (`is_admin` 체크)

---

## 실행 방법

```bash
# 1. 가상환경 생성 및 활성화
python -m venv venv
venv\Scripts\activate  # Windows 기준

# 2. 패키지 설치
pip install -r requirements.txt

# 3. 앱 실행
python app.py

python -m venv venv
venv\Scripts\activate  # Windows
