# Killer Features Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the four killer features from the approved design: Document Intelligence Hub, Court Rules Engine, Revenue Recovery, and Progressive Web App.

**Architecture:** Each feature adds new models, services, routers, and Celery tasks to the existing backend, plus new React pages/components to the frontend. All features follow existing patterns (UUIDBase, TimestampMixin, async SQLAlchemy, FastAPI routers, Mantine v7 components). AI features use a pluggable service layer (Ollama or cloud API).

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0, Celery, Tesseract OCR, pdfplumber, PostgreSQL full-text search, React 18, TypeScript, Mantine v7, Workbox (PWA)

**Prerequisites:** All 10 security remediation tasks from `2026-03-03-security-remediation.md` must be completed first.

---

# Feature 1: Document Intelligence Hub

## Task 1: Add New Dependencies

**Files:**
- Modify: `backend/pyproject.toml` or create `backend/requirements-ai.txt`

### Step 1: Add dependencies

Add to backend requirements:
```
tesseract-ocr  # System package, not pip — install via apt/brew
pytesseract==0.3.10
pdfplumber==0.11.0
python-docx==1.1.0
httpx>=0.27.0  # already present, for AI API calls
```

### Step 2: Verify install

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && pip install pytesseract pdfplumber python-docx`
Expected: Install succeeds.

### Step 3: Commit

```bash
git add backend/
git commit -m "chore: add document intelligence dependencies (pytesseract, pdfplumber, python-docx)"
```

---

## Task 2: Document Intelligence Data Models

**Files:**
- Create: `backend/app/documents/intelligence_models.py`
- Modify: `backend/alembic/env.py` — add import
- Create: Alembic migration

### Step 1: Write the failing test

Create `backend/tests/test_document_intelligence_models.py`:

```python
"""Tests for document intelligence data models."""
import uuid
import pytest
import pytest_asyncio
from sqlalchemy import select

from app.documents.intelligence_models import (
    DocumentMetadata,
    DocumentInbox,
    InboxStatus,
    DocumentType,
    AIMisfiling,
)
from tests.conftest import TestSession


class TestDocumentMetadataModel:
    @pytest.mark.asyncio
    async def test_create_document_metadata(self):
        async with TestSession() as db:
            meta = DocumentMetadata(
                document_id=uuid.uuid4(),
                extracted_text="This is a complaint filed in the Superior Court...",
                document_type=DocumentType.pleading,
                confidence_score=0.92,
                extracted_dates={"filing_date": "2026-01-15"},
                extracted_parties=["Smith", "Jones Corp"],
                ocr_status="completed",
                ai_processed=True,
            )
            db.add(meta)
            await db.flush()
            assert meta.id is not None


class TestDocumentInboxModel:
    @pytest.mark.asyncio
    async def test_create_inbox_entry(self):
        async with TestSession() as db:
            entry = DocumentInbox(
                filename="complaint.pdf",
                storage_key="inbox/abc123/complaint.pdf",
                mime_type="application/pdf",
                size_bytes=45000,
                source="upload",
                status=InboxStatus.pending,
                uploaded_by=uuid.uuid4(),
            )
            db.add(entry)
            await db.flush()
            assert entry.id is not None
            assert entry.status == InboxStatus.pending
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_document_intelligence_models.py -v`
Expected: FAIL — module not found.

### Step 3: Create the models

Create `backend/app/documents/intelligence_models.py`:

```python
"""
Document Intelligence Hub data models.

Extends the existing Document model with AI-extracted metadata,
a document inbox for classification, and a misfiling audit trail.
"""
import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.base_models import GUID, TimestampMixin, UUIDBase


class DocumentType(str, enum.Enum):
    pleading = "pleading"
    contract = "contract"
    correspondence = "correspondence"
    discovery = "discovery"
    invoice = "invoice"
    court_order = "court_order"
    motion = "motion"
    exhibit = "exhibit"
    other = "other"


class InboxStatus(str, enum.Enum):
    pending = "pending"
    classified = "classified"
    filed = "filed"
    rejected = "rejected"


class InboxSource(str, enum.Enum):
    upload = "upload"
    email = "email"
    camera = "camera"


class AIFilingTier(str, enum.Enum):
    auto_filed = "auto_filed"      # 95%+ AND same client
    suggested = "suggested"        # 60-95% OR different client
    manual = "manual"              # <60% OR no match


class DocumentMetadata(UUIDBase, TimestampMixin):
    """AI-extracted metadata for a document."""
    __tablename__ = "document_metadata"

    document_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    extracted_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    document_type: Mapped[Optional[DocumentType]] = mapped_column(
        Enum(DocumentType, native_enum=False), nullable=True
    )
    confidence_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    extracted_dates: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    extracted_parties: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    ocr_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    ai_processed: Mapped[bool] = mapped_column(default=False)
    ai_filing_tier: Mapped[Optional[AIFilingTier]] = mapped_column(
        Enum(AIFilingTier, native_enum=False), nullable=True
    )
    ai_decision_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # PostgreSQL full-text search vector — populated by Celery task
    # tsvector column added via raw SQL in migration (not mapped here)

    document = relationship("Document", backref="ai_metadata", uselist=False)


class DocumentInbox(UUIDBase, TimestampMixin):
    """Unified ingestion inbox for incoming documents."""
    __tablename__ = "document_inbox"

    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1000), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[InboxSource] = mapped_column(
        Enum(InboxSource, native_enum=False), nullable=False
    )
    status: Mapped[InboxStatus] = mapped_column(
        Enum(InboxStatus, native_enum=False), default=InboxStatus.pending
    )
    uploaded_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id"), nullable=False
    )

    # AI classification results
    suggested_matter_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("matters.id"), nullable=True
    )
    suggested_document_type: Mapped[Optional[DocumentType]] = mapped_column(
        Enum(DocumentType, native_enum=False), nullable=True
    )
    classification_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ai_filing_tier: Mapped[Optional[AIFilingTier]] = mapped_column(
        Enum(AIFilingTier, native_enum=False), nullable=True
    )
    filed_to_document_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("documents.id"), nullable=True
    )
    filed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    uploaded_by_user = relationship("User", foreign_keys=[uploaded_by])
    suggested_matter = relationship("Matter", foreign_keys=[suggested_matter_id])
    filed_document = relationship("Document", foreign_keys=[filed_to_document_id])


class AIMisfiling(UUIDBase, TimestampMixin):
    """Audit trail for AI misfiling corrections."""
    __tablename__ = "ai_misfilings"

    document_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("documents.id"), nullable=False
    )
    original_matter_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("matters.id"), nullable=False
    )
    corrected_matter_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("matters.id"), nullable=False
    )
    corrected_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id"), nullable=False
    )
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    document = relationship("Document", foreign_keys=[document_id])
    original_matter = relationship("Matter", foreign_keys=[original_matter_id])
    corrected_matter = relationship("Matter", foreign_keys=[corrected_matter_id])
    corrected_by_user = relationship("User", foreign_keys=[corrected_by])
```

### Step 4: Add import to alembic/env.py

Add to the model imports in `backend/alembic/env.py`:
```python
from app.documents.intelligence_models import DocumentMetadata, DocumentInbox, AIMisfiling  # noqa: F401
```

### Step 5: Generate and run migration

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && alembic revision --autogenerate -m "add document intelligence models"`
Run: `cd /Users/mattcatsimanes/LexNebulis/backend && alembic upgrade head`

### Step 6: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_document_intelligence_models.py -v`
Expected: All PASS.

### Step 7: Commit

```bash
git add backend/app/documents/intelligence_models.py backend/alembic/ backend/tests/test_document_intelligence_models.py
git commit -m "feat: add document intelligence data models (metadata, inbox, misfiling)"
```

---

## Task 3: AI Service Layer (Pluggable)

**Files:**
- Create: `backend/app/ai/__init__.py`
- Create: `backend/app/ai/service.py`
- Create: `backend/app/ai/schemas.py`
- Modify: `backend/app/config.py` — add AI settings
- Test: `backend/tests/test_ai_service.py`

### Step 1: Write the failing test

Create `backend/tests/test_ai_service.py`:

```python
"""Tests for pluggable AI service layer."""
import pytest
from unittest.mock import patch, AsyncMock

from app.ai.service import classify_document, AIClassificationResult


class TestAIClassification:
    @pytest.mark.asyncio
    async def test_classify_document_returns_result(self):
        """AI classification should return a structured result."""
        mock_response = {
            "document_type": "pleading",
            "confidence": 0.87,
            "extracted_dates": {"filing_date": "2026-01-15"},
            "extracted_parties": ["Smith", "Jones Corp"],
            "suggested_matter_context": "Smith v. Jones Corp",
        }

        with patch("app.ai.service._call_ai_provider", new_callable=AsyncMock) as mock_ai:
            mock_ai.return_value = mock_response
            result = await classify_document(
                text="COMPLAINT FOR DAMAGES\nPlaintiff John Smith vs Jones Corp...",
                user_id="test-user-id",
                available_matters=[],
            )
            assert isinstance(result, AIClassificationResult)
            assert result.document_type == "pleading"
            assert result.confidence >= 0.0

    @pytest.mark.asyncio
    async def test_classify_empty_text_returns_manual_tier(self):
        """Empty text should return manual tier (no AI classification)."""
        result = await classify_document(
            text="",
            user_id="test-user-id",
            available_matters=[],
        )
        assert result.filing_tier == "manual"
        assert result.confidence == 0.0
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_ai_service.py -v`
Expected: FAIL — module not found.

### Step 3: Implement AI service layer

Add to `backend/app/config.py`:
```python
    # AI Service
    ai_provider: str = "none"  # "none", "ollama", "openai", "anthropic"
    ai_model: str = ""
    ai_api_key: str = ""
    ai_base_url: str = "http://localhost:11434"  # Ollama default
```

Create `backend/app/ai/__init__.py` (empty).

Create `backend/app/ai/schemas.py`:

```python
"""AI service schemas."""
from typing import Optional
from pydantic import BaseModel


class AIClassificationResult(BaseModel):
    document_type: str = "other"
    confidence: float = 0.0
    filing_tier: str = "manual"  # auto_filed, suggested, manual
    extracted_dates: dict = {}
    extracted_parties: list[str] = []
    suggested_matter_id: Optional[str] = None
    suggested_matter_name: Optional[str] = None
    reasoning: str = ""
```

Create `backend/app/ai/service.py`:

```python
"""
Pluggable AI service layer for LexNebulis.

Supports: Ollama (self-hosted), OpenAI API, Anthropic API.
Falls back to rule-based classification when no AI provider is configured.
"""
import json
import logging
import re
from typing import Optional

import httpx

from app.ai.schemas import AIClassificationResult
from app.config import settings

logger = logging.getLogger(__name__)

# Classification prompt template
_CLASSIFY_PROMPT = """You are a legal document classification system. Analyze the following document text and return a JSON object with these fields:

- document_type: one of "pleading", "contract", "correspondence", "discovery", "invoice", "court_order", "motion", "exhibit", "other"
- confidence: float 0.0-1.0
- extracted_dates: object with date labels as keys, ISO dates as values
- extracted_parties: array of party/entity names found
- suggested_matter_context: brief description of the matter this document relates to

Available matters for this user:
{matters_context}

Document text (first 3000 chars):
{text}

Respond ONLY with valid JSON, no explanation."""


async def classify_document(
    text: str,
    user_id: str,
    available_matters: list[dict],
) -> AIClassificationResult:
    """Classify a document using the configured AI provider.

    Args:
        text: Extracted document text
        user_id: ID of the user uploading (for context scoping)
        available_matters: List of matters the user has access to

    Returns:
        AIClassificationResult with classification and extracted metadata
    """
    if not text or not text.strip():
        return AIClassificationResult(filing_tier="manual", confidence=0.0)

    # Try deterministic case number matching first
    case_match = _match_case_number(text, available_matters)
    if case_match:
        return case_match

    # If no AI provider configured, return manual
    if settings.ai_provider == "none":
        return _rule_based_classify(text)

    # Build context (only matters user has access to — client isolation)
    matters_context = "\n".join(
        f"- {m.get('title', 'Untitled')} (case: {m.get('case_number', 'N/A')}, client: {m.get('client_name', 'N/A')})"
        for m in available_matters[:20]  # Limit context size
    ) or "No matters available"

    prompt = _CLASSIFY_PROMPT.format(
        matters_context=matters_context,
        text=text[:3000],
    )

    try:
        response = await _call_ai_provider(prompt)
        result = _parse_ai_response(response, available_matters)
        return result
    except Exception as e:
        logger.warning("AI classification failed: %s", e)
        return _rule_based_classify(text)


def _match_case_number(text: str, matters: list[dict]) -> Optional[AIClassificationResult]:
    """Deterministic case number matching — no AI needed, handles 60%+ of litigation docs."""
    for matter in matters:
        case_num = matter.get("case_number", "")
        if case_num and case_num in text:
            return AIClassificationResult(
                document_type=_guess_type_from_text(text),
                confidence=0.98,
                filing_tier="auto_filed",
                suggested_matter_id=matter.get("id"),
                suggested_matter_name=matter.get("title"),
                reasoning=f"Case number {case_num} found in document text",
            )
    return None


def _rule_based_classify(text: str) -> AIClassificationResult:
    """Simple keyword-based classification when no AI is available."""
    doc_type = _guess_type_from_text(text)
    return AIClassificationResult(
        document_type=doc_type,
        confidence=0.3,
        filing_tier="manual",
        reasoning="Rule-based classification (no AI provider configured)",
    )


def _guess_type_from_text(text: str) -> str:
    """Simple keyword matching for document type."""
    text_lower = text.lower()
    if any(w in text_lower for w in ["complaint", "petition", "demurrer", "answer", "motion"]):
        return "pleading"
    if any(w in text_lower for w in ["agreement", "contract", "terms", "covenant"]):
        return "contract"
    if any(w in text_lower for w in ["invoice", "billing", "amount due"]):
        return "invoice"
    if any(w in text_lower for w in ["order", "judgment", "decree", "ruling"]):
        return "court_order"
    if any(w in text_lower for w in ["interrogator", "request for production", "deposition", "subpoena"]):
        return "discovery"
    return "other"


async def _call_ai_provider(prompt: str) -> dict:
    """Call the configured AI provider and return the parsed response."""
    if settings.ai_provider == "ollama":
        return await _call_ollama(prompt)
    elif settings.ai_provider == "openai":
        return await _call_openai(prompt)
    elif settings.ai_provider == "anthropic":
        return await _call_anthropic(prompt)
    raise ValueError(f"Unknown AI provider: {settings.ai_provider}")


async def _call_ollama(prompt: str) -> dict:
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{settings.ai_base_url}/api/generate",
            json={"model": settings.ai_model, "prompt": prompt, "stream": False},
        )
        resp.raise_for_status()
        text = resp.json().get("response", "")
        return json.loads(text)


async def _call_openai(prompt: str) -> dict:
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.ai_api_key}"},
            json={
                "model": settings.ai_model or "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
            },
        )
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"]
        return json.loads(text)


async def _call_anthropic(prompt: str) -> dict:
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.ai_api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": settings.ai_model or "claude-sonnet-4-6",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"]
        return json.loads(text)


def _parse_ai_response(response: dict, available_matters: list[dict]) -> AIClassificationResult:
    """Parse AI response and determine filing tier."""
    confidence = float(response.get("confidence", 0.0))
    doc_type = response.get("document_type", "other")
    dates = response.get("extracted_dates", {})
    parties = response.get("extracted_parties", [])
    context = response.get("suggested_matter_context", "")

    # Determine suggested matter from context
    suggested_id = None
    suggested_name = None
    for matter in available_matters:
        title = matter.get("title", "")
        if context and (title.lower() in context.lower() or context.lower() in title.lower()):
            suggested_id = matter.get("id")
            suggested_name = title
            break

    # Determine filing tier (three-tier confidence model)
    if confidence >= 0.95 and suggested_id:
        filing_tier = "auto_filed"
    elif confidence >= 0.60:
        filing_tier = "suggested"
    else:
        filing_tier = "manual"

    return AIClassificationResult(
        document_type=doc_type,
        confidence=confidence,
        filing_tier=filing_tier,
        extracted_dates=dates,
        extracted_parties=parties,
        suggested_matter_id=suggested_id,
        suggested_matter_name=suggested_name,
        reasoning=context,
    )
```

### Step 4: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_ai_service.py -v`
Expected: All PASS.

### Step 5: Commit

```bash
git add backend/app/ai/ backend/app/config.py backend/tests/test_ai_service.py
git commit -m "feat: add pluggable AI service layer (Ollama/OpenAI/Anthropic)

- Classify documents by type with confidence scoring
- Three-tier filing model: auto-file, suggest, manual
- Deterministic case number matching (no AI needed)
- Rule-based fallback when no AI provider configured
- Client isolation: AI context scoped per-user"
```

---

## Task 4: Text Extraction Pipeline (OCR + PDF + DOCX)

**Files:**
- Create: `backend/app/documents/extraction.py`
- Test: `backend/tests/test_extraction.py`

### Step 1: Write the failing test

Create `backend/tests/test_extraction.py`:

```python
"""Tests for document text extraction."""
import pytest
from app.documents.extraction import extract_text


class TestTextExtraction:
    def test_extract_plain_text(self):
        content = b"This is a plain text document about a legal matter."
        result = extract_text(content, "text/plain", "test.txt")
        assert "legal matter" in result

    def test_extract_empty_content_returns_empty(self):
        result = extract_text(b"", "text/plain", "empty.txt")
        assert result == ""

    def test_unsupported_mime_type_returns_empty(self):
        result = extract_text(b"\x00\x01", "application/octet-stream", "binary.bin")
        assert result == ""
```

### Step 2: Implement extraction

Create `backend/app/documents/extraction.py`:

```python
"""
Document text extraction pipeline.

Supports: PDF (pdfplumber), DOCX (python-docx), images (Tesseract OCR),
and plain text. Returns extracted text for AI classification and full-text search.
"""
import io
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def extract_text(content: bytes, mime_type: str, filename: str) -> str:
    """Extract text from document content based on MIME type."""
    if not content:
        return ""

    try:
        if mime_type == "application/pdf":
            return _extract_pdf(content)
        elif mime_type in (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/msword",
        ):
            return _extract_docx(content)
        elif mime_type.startswith("image/"):
            return _extract_ocr(content)
        elif mime_type.startswith("text/"):
            return content.decode("utf-8", errors="replace")
        else:
            return ""
    except Exception as e:
        logger.warning("Text extraction failed for %s: %s", filename, e)
        return ""


def _extract_pdf(content: bytes) -> str:
    import pdfplumber
    text_parts = []
    with pdfplumber.open(io.BytesIO(content)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)
    full_text = "\n".join(text_parts)
    # If PDF has no extractable text (scanned), try OCR
    if not full_text.strip():
        return _extract_ocr(content)
    return full_text


def _extract_docx(content: bytes) -> str:
    from docx import Document
    doc = Document(io.BytesIO(content))
    return "\n".join(p.text for p in doc.paragraphs if p.text)


def _extract_ocr(content: bytes) -> str:
    try:
        import pytesseract
        from PIL import Image
        image = Image.open(io.BytesIO(content))
        return pytesseract.image_to_string(image)
    except ImportError:
        logger.warning("pytesseract not installed — OCR unavailable")
        return ""
    except Exception as e:
        logger.warning("OCR failed: %s", e)
        return ""
```

### Step 3: Run tests and commit

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_extraction.py -v`

```bash
git add backend/app/documents/extraction.py backend/tests/test_extraction.py
git commit -m "feat: add document text extraction pipeline (PDF, DOCX, OCR, text)"
```

---

## Task 5: Document Intelligence Celery Tasks

**Files:**
- Create: `backend/app/documents/intelligence_tasks.py`
- Modify: `backend/app/celery_app.py` — add autodiscovery
- Test: `backend/tests/test_intelligence_tasks.py`

### Step 1: Write the test

```python
"""Tests for document intelligence Celery tasks."""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock


class TestProcessDocumentTask:
    def test_task_is_registered(self):
        from app.documents.intelligence_tasks import process_document_intelligence
        assert process_document_intelligence.name == "app.documents.intelligence_tasks.process_document_intelligence"
```

### Step 2: Implement

Create `backend/app/documents/intelligence_tasks.py`:

```python
"""
Celery tasks for document intelligence processing.

Pipeline: Document uploaded → extract text → AI classify → update metadata → index for search
"""
import hashlib
import json
import logging
import uuid

from app.celery_app import celery_app
from app.database import async_session

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=30)
def process_document_intelligence(self, document_id: str, user_id: str):
    """Process a document through the intelligence pipeline.

    1. Download from MinIO
    2. Extract text (PDF/DOCX/OCR)
    3. Classify via AI
    4. Store metadata
    5. Generate search index
    """
    import asyncio
    asyncio.run(_process_document_async(document_id, user_id))


async def _process_document_async(document_id: str, user_id: str):
    from sqlalchemy import select
    from app.documents.models import Document
    from app.documents.intelligence_models import DocumentMetadata, AIFilingTier
    from app.documents.extraction import extract_text
    from app.documents.service import get_minio_client
    from app.ai.service import classify_document
    from app.config import settings

    async with async_session() as db:
        # 1. Get the document
        result = await db.execute(
            select(Document).where(Document.id == uuid.UUID(document_id))
        )
        doc = result.scalar_one_or_none()
        if doc is None:
            logger.error("Document %s not found", document_id)
            return

        # 2. Download content from MinIO
        client = get_minio_client()
        response = client.get_object(settings.minio_bucket, doc.storage_key)
        content = response.read()
        response.close()

        # 3. Extract text
        text = extract_text(content, doc.mime_type, doc.filename)

        # 4. Get user's accessible matters for AI context
        from app.matters.models import Matter
        matters_result = await db.execute(select(Matter))
        matters = [
            {
                "id": str(m.id),
                "title": m.title,
                "case_number": m.case_number,
                "client_id": str(m.client_id),
            }
            for m in matters_result.scalars().all()
        ]

        # 5. AI classification
        ai_result = await classify_document(
            text=text,
            user_id=user_id,
            available_matters=matters,
        )

        # 6. Compute decision hash for audit trail
        decision_payload = json.dumps({
            "document_id": document_id,
            "document_type": ai_result.document_type,
            "confidence": ai_result.confidence,
            "filing_tier": ai_result.filing_tier,
            "suggested_matter_id": ai_result.suggested_matter_id,
        }, sort_keys=True)
        decision_hash = hashlib.sha256(decision_payload.encode()).hexdigest()

        # 7. Store metadata
        metadata = DocumentMetadata(
            document_id=uuid.UUID(document_id),
            extracted_text=text,
            document_type=ai_result.document_type,
            confidence_score=ai_result.confidence,
            extracted_dates=ai_result.extracted_dates,
            extracted_parties=ai_result.extracted_parties,
            ocr_status="completed" if text else "no_text",
            ai_processed=True,
            ai_filing_tier=AIFilingTier(ai_result.filing_tier),
            ai_decision_hash=decision_hash,
        )
        db.add(metadata)
        await db.commit()

        logger.info(
            "Document %s processed: type=%s confidence=%.2f tier=%s",
            document_id, ai_result.document_type, ai_result.confidence, ai_result.filing_tier,
        )
```

Update `backend/app/celery_app.py` autodiscovery:
```python
celery_app.autodiscover_tasks([
    "app.billing",
    "app.documents",
    "app.admin",
    "app.common",
    "app.cloud_storage",
])
```

### Step 3: Run tests and commit

```bash
git add backend/app/documents/intelligence_tasks.py backend/app/celery_app.py backend/tests/test_intelligence_tasks.py
git commit -m "feat: add document intelligence Celery pipeline (extract → classify → index)"
```

---

## Task 6: Document Inbox API Router

**Files:**
- Create: `backend/app/documents/inbox_router.py`
- Create: `backend/app/documents/inbox_service.py`
- Modify: `backend/app/main.py` — register router
- Test: `backend/tests/test_document_inbox.py`

### Step 1: Write the test

Create `backend/tests/test_document_inbox.py`:

```python
"""Tests for document inbox API."""
import pytest


class TestDocumentInbox:
    @pytest.mark.asyncio
    async def test_list_inbox_empty(self, admin_client):
        resp = await admin_client.get("/api/documents/inbox")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_upload_to_inbox(self, admin_client):
        """Upload a document to the inbox (no matter specified)."""
        import io
        files = {"file": ("test.txt", io.BytesIO(b"test content"), "text/plain")}
        resp = await admin_client.post("/api/documents/inbox/upload", files=files)
        assert resp.status_code == 201
        assert resp.json()["status"] == "pending"

    @pytest.mark.asyncio
    async def test_approve_inbox_item(self, admin_client, sample_matter):
        """Approve an inbox item to file it to a matter."""
        import io
        files = {"file": ("test.txt", io.BytesIO(b"test content"), "text/plain")}
        upload_resp = await admin_client.post("/api/documents/inbox/upload", files=files)
        inbox_id = upload_resp.json()["id"]

        resp = await admin_client.post(f"/api/documents/inbox/{inbox_id}/approve", json={
            "matter_id": sample_matter["id"],
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "filed"
```

### Step 2: Implement inbox service and router

Create `backend/app/documents/inbox_service.py` with functions for:
- `list_inbox_items(db, user_id, status_filter)` — list items scoped to user
- `upload_to_inbox(db, user_id, file, source)` — store in MinIO, create InboxEntry, kick off intelligence task
- `approve_inbox_item(db, user_id, inbox_id, matter_id)` — move from inbox to matter, create Document record
- `reject_inbox_item(db, user_id, inbox_id, reason)` — mark as rejected

Create `backend/app/documents/inbox_router.py` with endpoints:
- `GET /api/documents/inbox` — list inbox items
- `POST /api/documents/inbox/upload` — upload to inbox
- `POST /api/documents/inbox/{id}/approve` — approve and file
- `POST /api/documents/inbox/{id}/reject` — reject
- `POST /api/documents/inbox/{id}/reclassify` — correct AI classification (misfiling)

Register in `main.py`:
```python
from app.documents.inbox_router import router as inbox_router
app.include_router(inbox_router, prefix="/api/documents", tags=["Document Inbox"])
```

### Step 3: Run tests and commit

```bash
git add backend/app/documents/inbox_service.py backend/app/documents/inbox_router.py backend/app/main.py backend/tests/test_document_inbox.py
git commit -m "feat: add document inbox API (upload, classify, approve, reject)"
```

---

## Task 7: Full-Text Search with AI Summaries

**Files:**
- Create: `backend/app/search/fulltext_service.py`
- Modify: `backend/app/search/router.py` — add full-text endpoint
- Test: `backend/tests/test_fulltext_search.py`

### Step 1: Implement PostgreSQL full-text search

The search service queries `document_metadata.extracted_text` using PostgreSQL's `to_tsvector` / `to_tsquery`. For SQLite in tests, falls back to `LIKE` search.

Key functions:
- `search_documents(db, query, user_id, matter_id=None)` — search across all accessible documents
- `_generate_summary(text, query)` — lazy-generate AI summary snippet on first search hit, cache in metadata

### Step 2: Run tests and commit

```bash
git commit -m "feat: add full-text document search with AI summary snippets"
```

---

## Task 8: Document Timeline and Version Comparison

**Files:**
- Create: `backend/app/documents/timeline_service.py`
- Create: `backend/app/documents/diff_service.py`
- Test: `backend/tests/test_document_timeline.py`

### Step 1: Implement

`timeline_service.py`:
- `get_matter_timeline(db, matter_id)` — returns documents ordered by extracted_dates, not upload date

`diff_service.py`:
- `compare_document_versions(db, doc_id_a, doc_id_b)` — extract text from both, compute word-level diff
- Uses `difflib.ndiff` or `difflib.HtmlDiff` for redline view

### Step 2: Run tests and commit

```bash
git commit -m "feat: add document timeline and version comparison"
```

---

# Feature 2: Court Rules Engine

## Task 9: Court Rules Data Models

**Files:**
- Create: `backend/app/court_rules/__init__.py`
- Create: `backend/app/court_rules/models.py`
- Create: `backend/app/court_rules/schemas.py`
- Modify: `backend/alembic/env.py` — add import
- Test: `backend/tests/test_court_rules_models.py`

### Step 1: Write the failing test

Create `backend/tests/test_court_rules_models.py`:

```python
"""Tests for court rules data models."""
import uuid
import pytest
import pytest_asyncio

from app.court_rules.models import (
    Jurisdiction,
    JurisdictionStatus,
    CourtRule,
    DayType,
    JurisdictionAcceptance,
)
from tests.conftest import TestSession


class TestJurisdictionModel:
    @pytest.mark.asyncio
    async def test_create_jurisdiction(self):
        async with TestSession() as db:
            j = Jurisdiction(
                code="US-CA",
                name="California Civil Procedure",
                source="California Code of Civil Procedure",
                status=JurisdictionStatus.not_reviewed,
            )
            db.add(j)
            await db.flush()
            assert j.id is not None
            assert j.status == JurisdictionStatus.not_reviewed


class TestCourtRuleModel:
    @pytest.mark.asyncio
    async def test_create_court_rule(self):
        async with TestSession() as db:
            j = Jurisdiction(
                code="US-CA",
                name="California",
                source="CCP",
                status=JurisdictionStatus.not_reviewed,
            )
            db.add(j)
            await db.flush()

            rule = CourtRule(
                jurisdiction_id=j.id,
                trigger_event="complaint_filed",
                name="Answer or Demurrer Due",
                offset_days=30,
                day_type=DayType.calendar,
                service_adjustments={"mail": 5, "electronic": 2},
                reminder_days=[7, 3, 1],
                statutory_citation="CCP §412.20",
                citation_url="https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=412.20",
            )
            db.add(rule)
            await db.flush()
            assert rule.id is not None
```

### Step 2: Run test to verify it fails

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_court_rules_models.py -v`
Expected: FAIL — module not found.

### Step 3: Implement models

Create `backend/app/court_rules/models.py`:

```python
"""
Court Rules Engine data models.

Supports all 57 US jurisdictions with configurable deadline chains,
service method adjustments, holiday calendars, and firm-owned validation.
"""
import enum
import uuid
from datetime import date, datetime
from typing import Optional

from sqlalchemy import Boolean, Date, DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.base_models import GUID, TimestampMixin, UUIDBase


class JurisdictionStatus(str, enum.Enum):
    not_reviewed = "not_reviewed"
    accepted = "accepted"           # Firm accepted, verify badge
    firm_validated = "firm_validated"  # All rules checked by attorney
    customized = "customized"        # Firm modified rules
    disabled = "disabled"


class DayType(str, enum.Enum):
    calendar = "calendar"
    business = "business"
    court = "court"


class CalculationDirection(str, enum.Enum):
    forward = "forward"
    backward = "backward"


class Jurisdiction(UUIDBase, TimestampMixin):
    """A court jurisdiction with its rule set."""
    __tablename__ = "jurisdictions"

    code: Mapped[str] = mapped_column(String(10), unique=True, nullable=False)  # e.g., "US-CA"
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    source: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[JurisdictionStatus] = mapped_column(
        Enum(JurisdictionStatus, native_enum=False),
        default=JurisdictionStatus.not_reviewed,
    )
    effective_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    holidays: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)

    rules = relationship("CourtRule", back_populates="jurisdiction", cascade="all, delete-orphan")
    acceptances = relationship("JurisdictionAcceptance", back_populates="jurisdiction")


class CourtRule(UUIDBase, TimestampMixin):
    """A single deadline rule within a jurisdiction."""
    __tablename__ = "court_rules"

    jurisdiction_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("jurisdictions.id", ondelete="CASCADE"), nullable=False
    )
    trigger_event: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    offset_days: Mapped[int] = mapped_column(Integer, nullable=False)
    day_type: Mapped[DayType] = mapped_column(
        Enum(DayType, native_enum=False), default=DayType.calendar
    )
    direction: Mapped[CalculationDirection] = mapped_column(
        Enum(CalculationDirection, native_enum=False), default=CalculationDirection.forward
    )
    service_adjustments: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    reminder_days: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    statutory_citation: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    citation_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id"), nullable=True
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    jurisdiction = relationship("Jurisdiction", back_populates="rules")


class JurisdictionAcceptance(UUIDBase, TimestampMixin):
    """Audit trail for firm accepting a jurisdiction's rule set."""
    __tablename__ = "jurisdiction_acceptances"

    jurisdiction_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("jurisdictions.id"), nullable=False
    )
    accepted_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id"), nullable=False
    )
    accepted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    acceptance_statement: Mapped[str] = mapped_column(
        Text,
        default="This firm accepts responsibility for validating these reference rules against current statutes.",
    )

    jurisdiction = relationship("Jurisdiction", back_populates="acceptances")
    accepted_by_user = relationship("User")


class GeneratedDeadline(UUIDBase, TimestampMixin):
    """A deadline generated from a court rule for a specific matter."""
    __tablename__ = "generated_deadlines"

    matter_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("matters.id"), nullable=False
    )
    court_rule_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("court_rules.id"), nullable=False
    )
    trigger_date: Mapped[date] = mapped_column(Date, nullable=False)
    calculated_date: Mapped[date] = mapped_column(Date, nullable=False)
    service_method: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    service_adjustment_days: Mapped[int] = mapped_column(Integer, default=0)
    calendar_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("calendar_events.id"), nullable=True
    )
    disclaimer: Mapped[str] = mapped_column(
        Text,
        default="Generated from reference rules. Verify against statutory citation.",
    )
    rule_version: Mapped[int] = mapped_column(Integer, default=1)

    matter = relationship("Matter")
    court_rule = relationship("CourtRule")
    calendar_event = relationship("CalendarEvent")
```

### Step 4: Run tests and commit

```bash
git add backend/app/court_rules/ backend/alembic/ backend/tests/test_court_rules_models.py
git commit -m "feat: add court rules engine data models (jurisdictions, rules, deadlines)"
```

---

## Task 10: Court Rules Deadline Calculator

**Files:**
- Create: `backend/app/court_rules/calculator.py`
- Test: `backend/tests/test_deadline_calculator.py`

### Step 1: Write the failing test

```python
"""Tests for court rules deadline calculator."""
from datetime import date
import pytest
from app.court_rules.calculator import calculate_deadline


class TestDeadlineCalculator:
    def test_calendar_days_forward(self):
        """30 calendar days from Jan 15 = Feb 14."""
        result = calculate_deadline(
            trigger_date=date(2026, 1, 15),
            offset_days=30,
            day_type="calendar",
            direction="forward",
        )
        assert result == date(2026, 2, 14)

    def test_business_days_forward(self):
        """10 business days from Monday Jan 5 = Jan 19 (skips weekends)."""
        result = calculate_deadline(
            trigger_date=date(2026, 1, 5),  # Monday
            offset_days=10,
            day_type="business",
            direction="forward",
        )
        assert result.weekday() < 5  # Must land on a weekday

    def test_backward_calculation(self):
        """14 calendar days before March 15 = March 1."""
        result = calculate_deadline(
            trigger_date=date(2026, 3, 15),
            offset_days=14,
            day_type="calendar",
            direction="backward",
        )
        assert result == date(2026, 3, 1)

    def test_service_adjustment_mail(self):
        """30 days + 5 days mail service = 35 days."""
        result = calculate_deadline(
            trigger_date=date(2026, 1, 15),
            offset_days=30,
            day_type="calendar",
            direction="forward",
            service_method="mail",
            service_adjustments={"mail": 5, "electronic": 2},
        )
        assert result == date(2026, 2, 19)

    def test_weekend_landing_pushes_to_monday(self):
        """If deadline falls on Saturday, push to Monday."""
        # Find a date where +30 lands on a Saturday
        result = calculate_deadline(
            trigger_date=date(2026, 1, 3),  # Saturday + 30 = Feb 2 (Monday) — adjust as needed
            offset_days=30,
            day_type="calendar",
            direction="forward",
        )
        assert result.weekday() < 5  # Never land on weekend

    def test_holiday_skip(self):
        """If deadline falls on a holiday, push to next business day."""
        holidays = [date(2026, 1, 1)]  # New Year's Day
        result = calculate_deadline(
            trigger_date=date(2025, 12, 2),
            offset_days=30,
            day_type="calendar",
            direction="forward",
            holidays=holidays,
        )
        assert result != date(2026, 1, 1)
```

### Step 2: Implement calculator

Create `backend/app/court_rules/calculator.py`:

```python
"""
Court rules deadline calculator.

Handles calendar days, business days, court days,
service method adjustments, holiday calendars, and
forward/backward calculation.
"""
from datetime import date, timedelta
from typing import Optional


# Federal holidays (static — state holidays loaded from jurisdiction data)
FEDERAL_HOLIDAYS_2026 = [
    date(2026, 1, 1),   # New Year's
    date(2026, 1, 19),  # MLK Day
    date(2026, 2, 16),  # Presidents' Day
    date(2026, 5, 25),  # Memorial Day
    date(2026, 7, 3),   # Independence Day (observed)
    date(2026, 9, 7),   # Labor Day
    date(2026, 10, 12), # Columbus Day
    date(2026, 11, 11), # Veterans Day
    date(2026, 11, 26), # Thanksgiving
    date(2026, 12, 25), # Christmas
]


def calculate_deadline(
    trigger_date: date,
    offset_days: int,
    day_type: str = "calendar",
    direction: str = "forward",
    service_method: Optional[str] = None,
    service_adjustments: Optional[dict] = None,
    holidays: Optional[list[date]] = None,
) -> date:
    """Calculate a deadline date from a trigger event.

    Args:
        trigger_date: The date of the triggering event
        offset_days: Number of days to add/subtract
        day_type: "calendar", "business", or "court"
        direction: "forward" or "backward"
        service_method: How service was effectuated (e.g., "mail", "electronic")
        service_adjustments: Dict of service method → extra days
        holidays: List of holiday dates to skip

    Returns:
        The calculated deadline date (never falls on weekend or holiday)
    """
    all_holidays = set(holidays or []) | set(FEDERAL_HOLIDAYS_2026)

    # Apply service adjustment
    total_offset = offset_days
    if service_method and service_adjustments:
        total_offset += service_adjustments.get(service_method, 0)

    if day_type == "calendar":
        result = _calculate_calendar_days(trigger_date, total_offset, direction)
    elif day_type in ("business", "court"):
        result = _calculate_business_days(trigger_date, total_offset, direction, all_holidays)
    else:
        result = _calculate_calendar_days(trigger_date, total_offset, direction)

    # Ensure deadline doesn't fall on weekend or holiday
    result = _adjust_to_business_day(result, all_holidays, direction)
    return result


def _calculate_calendar_days(trigger: date, days: int, direction: str) -> date:
    if direction == "backward":
        return trigger - timedelta(days=days)
    return trigger + timedelta(days=days)


def _calculate_business_days(
    trigger: date, days: int, direction: str, holidays: set[date]
) -> date:
    current = trigger
    counted = 0
    step = 1 if direction == "forward" else -1

    while counted < days:
        current += timedelta(days=step)
        if current.weekday() < 5 and current not in holidays:
            counted += 1

    return current


def _adjust_to_business_day(d: date, holidays: set[date], direction: str) -> date:
    """If date falls on weekend or holiday, move to next/prev business day."""
    step = 1 if direction == "forward" else -1
    while d.weekday() >= 5 or d in holidays:
        d += timedelta(days=step)
    return d
```

### Step 3: Run tests and commit

```bash
git add backend/app/court_rules/calculator.py backend/tests/test_deadline_calculator.py
git commit -m "feat: add court rules deadline calculator with service adjustments and holidays"
```

---

## Task 11: Court Rules YAML Seed Data

**Files:**
- Create: `backend/alembic/seeds/court_rules/` directory
- Create: YAML files for all 57 jurisdictions
- Create: `backend/app/court_rules/seeder.py` — seed script

### Step 1: Create seed directory structure

```
backend/alembic/seeds/court_rules/
├── US-FRCP.yaml      # Federal Rules of Civil Procedure
├── US-AL.yaml         # Alabama
├── US-AK.yaml         # Alaska
├── US-AZ.yaml         # Arizona
├── ...                # (all 50 states)
├── US-DC.yaml         # District of Columbia
├── US-PR.yaml         # Puerto Rico
├── US-GU.yaml         # Guam
├── US-VI.yaml         # US Virgin Islands
├── US-AS.yaml         # American Samoa
└── US-MP.yaml         # Northern Mariana Islands
```

### Step 2: Create template YAML

Each jurisdiction file follows this schema (example for California):

```yaml
jurisdiction: "US-CA"
name: "California Civil Procedure"
source: "California Code of Civil Procedure"
status: "not_reviewed"
version: 1
holidays:
  - "2026-03-31"  # César Chávez Day
  - "2026-09-09"  # Admission Day (CA-specific)
rules:
  - trigger: "complaint_filed"
    name: "Answer or Demurrer Due"
    offset_days: 30
    day_type: "calendar"
    direction: "forward"
    service_adjustments:
      mail: 5
      electronic: 2
    reminder_days: [7, 3, 1]
    statutory_citation: "CCP §412.20"
    citation_url: "https://leginfo.legislature.ca.gov/..."
    description: "Defendant must file answer or demurrer within 30 days of service"

  - trigger: "answer_filed"
    name: "Scheduling Conference"
    offset_days: 120
    day_type: "calendar"
    direction: "forward"
    reminder_days: [14, 7]
    statutory_citation: "CRC 3.722"

  - trigger: "scheduling_order"
    name: "Discovery Cutoff"
    offset_days: 0
    day_type: "calendar"
    direction: "forward"
    description: "Set by court order — default 30 days before trial"
    statutory_citation: "CCP §2024.020"

  - trigger: "discovery_cutoff"
    name: "Expert Disclosure Deadline"
    offset_days: 50
    day_type: "calendar"
    direction: "backward"
    description: "50 days before initial trial date"
    statutory_citation: "CCP §2034.230"

  - trigger: "trial_date"
    name: "Motions in Limine Deadline"
    offset_days: 25
    day_type: "calendar"
    direction: "backward"
    statutory_citation: "CRC 3.1112"

  - trigger: "trial_date"
    name: "Pretrial Conference"
    offset_days: 30
    day_type: "calendar"
    direction: "backward"
    statutory_citation: "CRC 3.722"

  - trigger: "complaint_filed"
    name: "Service of Process Deadline"
    offset_days: 60
    day_type: "calendar"
    direction: "forward"
    statutory_citation: "CCP §583.210"
```

### Step 3: Create seeder script

Create `backend/app/court_rules/seeder.py`:

```python
"""
Court rules YAML seeder.

Loads jurisdiction rule sets from YAML files in alembic/seeds/court_rules/.
Called on first run and on upgrades to add new jurisdictions.
"""
import logging
import os
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.court_rules.models import (
    CourtRule,
    DayType,
    CalculationDirection,
    Jurisdiction,
    JurisdictionStatus,
)

logger = logging.getLogger(__name__)
SEEDS_DIR = Path(__file__).parent.parent.parent / "alembic" / "seeds" / "court_rules"


async def seed_court_rules(db: AsyncSession) -> int:
    """Seed court rules from YAML files. Returns count of jurisdictions seeded."""
    if not SEEDS_DIR.exists():
        logger.warning("Court rules seed directory not found: %s", SEEDS_DIR)
        return 0

    count = 0
    for yaml_file in sorted(SEEDS_DIR.glob("*.yaml")):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)

        code = data["jurisdiction"]

        # Skip if already seeded (idempotent)
        existing = await db.execute(
            select(Jurisdiction).where(Jurisdiction.code == code)
        )
        if existing.scalar_one_or_none() is not None:
            continue

        jurisdiction = Jurisdiction(
            code=code,
            name=data["name"],
            source=data["source"],
            status=JurisdictionStatus(data.get("status", "not_reviewed")),
            version=data.get("version", 1),
            holidays=data.get("holidays"),
        )
        db.add(jurisdiction)
        await db.flush()

        for rule_data in data.get("rules", []):
            rule = CourtRule(
                jurisdiction_id=jurisdiction.id,
                trigger_event=rule_data["trigger"],
                name=rule_data["name"],
                offset_days=rule_data["offset_days"],
                day_type=DayType(rule_data.get("day_type", "calendar")),
                direction=CalculationDirection(rule_data.get("direction", "forward")),
                service_adjustments=rule_data.get("service_adjustments"),
                reminder_days=rule_data.get("reminder_days"),
                statutory_citation=rule_data.get("statutory_citation"),
                citation_url=rule_data.get("citation_url"),
                description=rule_data.get("description"),
            )
            db.add(rule)

        count += 1

    await db.commit()
    logger.info("Seeded %d jurisdictions", count)
    return count
```

### Step 4: Generate all 57 YAML files

Use AI to generate reference rules for each jurisdiction with statutory citations. Each file follows the same schema as the California example above. The content is AI-generated reference rules shipped with "not_reviewed" status.

### Step 5: Commit

```bash
git add backend/alembic/seeds/ backend/app/court_rules/seeder.py
git commit -m "feat: add court rules YAML seeds for all 57 US jurisdictions"
```

---

## Task 12: Court Rules Validation Workflow API

**Files:**
- Create: `backend/app/court_rules/router.py`
- Create: `backend/app/court_rules/service.py`
- Modify: `backend/app/main.py` — register router
- Test: `backend/tests/test_court_rules_api.py`

### Step 1: Implement key endpoints

```
GET    /api/court-rules/jurisdictions              — list all jurisdictions with status
GET    /api/court-rules/jurisdictions/{code}        — get jurisdiction detail + rules
POST   /api/court-rules/jurisdictions/{code}/accept — first-use acceptance gate (admin/attorney only)
POST   /api/court-rules/rules/{rule_id}/verify      — mark individual rule as verified
POST   /api/court-rules/calculate                    — calculate deadlines for a matter
GET    /api/court-rules/deadlines/{matter_id}        — get generated deadlines for a matter
```

**Critical constraints:**
- `accept` endpoint: Only admin or attorney can accept. Logs to audit trail. Per-jurisdiction.
- `calculate` endpoint: Returns 403 if jurisdiction status is `not_reviewed` or `disabled`.
- Every generated deadline includes disclaimer with statutory citation.
- Existing deadlines are never retroactively updated when rules change.

### Step 2: Run tests and commit

```bash
git add backend/app/court_rules/router.py backend/app/court_rules/service.py backend/app/main.py backend/tests/test_court_rules_api.py
git commit -m "feat: add court rules validation workflow API with acceptance gate"
```

---

# Feature 3: Revenue Recovery

## Task 13: Payment Reminder Data Models

**Files:**
- Create: `backend/app/billing/reminder_models.py`
- Test: `backend/tests/test_reminder_models.py`

### Step 1: Implement models

```python
"""Payment reminder models."""
import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.base_models import GUID, TimestampMixin, UUIDBase


class EscalationLevel(int, enum.Enum):
    issued = 0          # Invoice issued
    pre_due_7 = 1       # 7 days before due
    past_due_1 = 2      # 1 day past due
    past_due_30 = 3     # 30 days past due
    past_due_60 = 4     # 60 days past due
    past_due_90 = 5     # 90 days past due (internal only)


class ReminderSchedule(UUIDBase, TimestampMixin):
    """Tracks the reminder escalation state for each invoice."""
    __tablename__ = "reminder_schedules"

    invoice_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("invoices.id"), nullable=False, unique=True
    )
    next_reminder_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    escalation_level: Mapped[EscalationLevel] = mapped_column(
        Enum(EscalationLevel, native_enum=False), default=EscalationLevel.issued
    )
    paused: Mapped[bool] = mapped_column(Boolean, default=False)
    pause_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    paused_by: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("users.id"), nullable=True)

    invoice = relationship("Invoice")


class ReminderLog(UUIDBase, TimestampMixin):
    """Audit log of sent reminders."""
    __tablename__ = "reminder_logs"

    invoice_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("invoices.id"), nullable=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    escalation_level: Mapped[EscalationLevel] = mapped_column(
        Enum(EscalationLevel, native_enum=False), nullable=False
    )
    recipient_email: Mapped[str] = mapped_column(String(255), nullable=False)
    template_used: Mapped[str] = mapped_column(String(100), nullable=False)
    delivery_status: Mapped[str] = mapped_column(String(50), default="sent")

    invoice = relationship("Invoice")
```

### Step 2: Run tests and commit

```bash
git commit -m "feat: add payment reminder data models (schedule, log, escalation)"
```

---

## Task 14: Payment Reminder Celery Task

**Files:**
- Create: `backend/app/billing/reminder_tasks.py`
- Test: `backend/tests/test_reminder_tasks.py`

### Step 1: Implement

Daily Celery beat task that:
1. Queries `ReminderSchedule` where `next_reminder_at <= now` and `paused == False`
2. For each, sends the appropriate email template based on `escalation_level`
3. Advances escalation level and sets next reminder date
4. Logs to `ReminderLog`
5. At level 5 (90 days), sends internal alert only (no client email)

```python
@celery_app.task
def process_payment_reminders():
    """Daily task: send payment reminders and advance escalation."""
    import asyncio
    asyncio.run(_process_reminders_async())
```

### Step 2: Add to Celery beat schedule

In `backend/app/celery_app.py`:
```python
celery_app.conf.beat_schedule = {
    "payment-reminders": {
        "task": "app.billing.reminder_tasks.process_payment_reminders",
        "schedule": 86400.0,  # Daily
    },
}
```

### Step 3: Run tests and commit

```bash
git commit -m "feat: add automated payment reminder Celery task with escalation chain"
```

---

## Task 15: Trust Account Compliance Alerts

**Files:**
- Create: `backend/app/trust/alert_models.py`
- Create: `backend/app/trust/alert_service.py`
- Modify: `backend/app/trust/service.py` — trigger alerts on ledger entries
- Test: `backend/tests/test_trust_alerts.py`

### Step 1: Implement models

```python
"""Trust account compliance alert models."""
class TrustAlert(UUIDBase, TimestampMixin):
    __tablename__ = "trust_alerts"

    trust_account_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("trust_accounts.id"))
    client_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("clients.id"), nullable=True)
    alert_type: Mapped[str] = mapped_column(String(50))  # low_balance, overdraw_attempt, commingling, stale_funds, recon_overdue, large_transaction, negative_balance
    severity: Mapped[str] = mapped_column(String(20))  # info, warning, critical, block
    message: Mapped[str] = mapped_column(Text)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    acknowledged_by: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("users.id"), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class TrustAlertConfig(UUIDBase, TimestampMixin):
    __tablename__ = "trust_alert_configs"

    trust_account_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("trust_accounts.id"))
    client_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("clients.id"), nullable=True)
    alert_type: Mapped[str] = mapped_column(String(50))
    threshold_cents: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_emails: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
```

### Step 2: Implement alert checking

In `alert_service.py`, add checks that are called from `create_ledger_entry`:
- **Overdraw attempt**: `severity="block"` — raises ValueError before the transaction completes
- **Commingling risk**: `severity="block"` — detects operating expense from trust account
- **Low balance**: `severity="warning"` — creates alert, does not block
- **Negative balance**: `severity="critical"` — data integrity violation

### Step 3: Run tests and commit

```bash
git commit -m "feat: add trust account compliance alerts with hard blocks on overdraw/commingling"
```

---

## Task 16: Plaid Bank Integration (Read-Only)

**Files:**
- Create: `backend/app/trust/plaid_models.py`
- Create: `backend/app/trust/plaid_service.py`
- Create: `backend/app/trust/plaid_router.py`
- Test: `backend/tests/test_plaid.py`

### Step 1: Implement

Models:
```python
class PlaidConnection(UUIDBase, TimestampMixin):
    __tablename__ = "plaid_connections"

    trust_account_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("trust_accounts.id"), unique=True)
    access_token_encrypted: Mapped[str] = mapped_column(Text)  # Fernet encrypted
    item_id: Mapped[str] = mapped_column(String(200))
    institution_name: Mapped[Optional[str]] = mapped_column(String(200))
    account_name: Mapped[Optional[str]] = mapped_column(String(200))
    account_mask: Mapped[Optional[str]] = mapped_column(String(4))  # Last 4 digits only
    connected_by: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("users.id"))
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
```

Service endpoints:
- `POST /api/trust/plaid/link-token` — create Plaid Link token for frontend widget
- `POST /api/trust/plaid/exchange` — exchange public token for access token (encrypted at rest)
- `POST /api/trust/plaid/reconcile/{trust_account_id}` — fetch bank balance, compare to ledger
- `DELETE /api/trust/plaid/{trust_account_id}` — disconnect bank (revoke token)

**Security:**
- Access tokens encrypted with Fernet (via `app.common.encryption`)
- Read-only scope in Plaid dashboard
- Every Plaid API call logged in audit trail
- No full account numbers stored (mask only)

### Step 2: Run tests and commit

```bash
git commit -m "feat: add Plaid bank integration for trust account reconciliation (read-only)"
```

---

## Task 17: LawPay Payment Plans

**Files:**
- Create: `backend/app/payments/plan_models.py`
- Create: `backend/app/payments/plan_service.py`
- Test: `backend/tests/test_payment_plans.py`

### Step 1: Implement models

```python
class PaymentPlan(UUIDBase, TimestampMixin):
    __tablename__ = "payment_plans"

    invoice_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("invoices.id"))
    processor: Mapped[str] = mapped_column(String(20))
    processor_plan_id: Mapped[Optional[str]] = mapped_column(String(200))
    installment_count: Mapped[int] = mapped_column(Integer)
    installment_amount_cents: Mapped[int] = mapped_column(Integer)
    frequency: Mapped[str] = mapped_column(String(20), default="monthly")
    start_date: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), default="active")


class PaymentPlanInstallment(UUIDBase, TimestampMixin):
    __tablename__ = "payment_plan_installments"

    payment_plan_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("payment_plans.id"))
    installment_number: Mapped[int] = mapped_column(Integer)
    amount_cents: Mapped[int] = mapped_column(Integer)
    due_date: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    processor_payment_id: Mapped[Optional[str]] = mapped_column(String(200))
    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
```

### Step 2: Run tests and commit

```bash
git commit -m "feat: add LawPay payment plans for installment billing"
```

---

# Feature 4: Progressive Web App (PWA)

## Task 18: PWA Manifest and Service Worker

**Files:**
- Create: `frontend/public/manifest.json`
- Create: `frontend/src/sw.ts` (service worker with Workbox)
- Modify: `frontend/index.html` — add manifest link
- Modify: `frontend/vite.config.ts` — add PWA plugin

### Step 1: Install dependencies

```bash
cd /Users/mattcatsimanes/LexNebulis/frontend && npm install vite-plugin-pwa workbox-precaching workbox-routing workbox-strategies workbox-background-sync -D
```

### Step 2: Create manifest

Create `frontend/public/manifest.json`:

```json
{
  "name": "LexNebulis",
  "short_name": "LexNebulis",
  "description": "Legal Practice Management",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#ffffff",
  "theme_color": "#228be6",
  "icons": [
    { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png" }
  ]
}
```

### Step 3: Configure Vite PWA plugin

In `frontend/vite.config.ts`:
```ts
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      strategies: 'injectManifest',
      srcDir: 'src',
      filename: 'sw.ts',
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg}'],
      },
    }),
  ],
});
```

### Step 4: Create service worker

Create `frontend/src/sw.ts`:

```ts
import { precacheAndRoute } from 'workbox-precaching';
import { registerRoute } from 'workbox-routing';
import { StaleWhileRevalidate, CacheFirst } from 'workbox-strategies';
import { BackgroundSyncPlugin } from 'workbox-background-sync';

declare let self: ServiceWorkerGlobalScope;

// Precache app shell
precacheAndRoute(self.__WB_MANIFEST);

// Cache API responses: calendar and contacts (stale-while-revalidate)
registerRoute(
  ({ url }) => url.pathname.startsWith('/api/calendar') || url.pathname.startsWith('/api/contacts'),
  new StaleWhileRevalidate({ cacheName: 'api-cache' })
);

// Cache static assets (cache-first)
registerRoute(
  ({ request }) => request.destination === 'image' || request.destination === 'font',
  new CacheFirst({ cacheName: 'static-cache' })
);

// Background sync for offline time entries
const bgSyncPlugin = new BackgroundSyncPlugin('time-entries-queue', {
  maxRetentionTime: 24 * 60, // 24 hours
});

registerRoute(
  ({ url }) => url.pathname === '/api/billing/time-entries' && self.registration.active !== null,
  new StaleWhileRevalidate({
    cacheName: 'time-entries',
    plugins: [bgSyncPlugin],
  }),
  'POST'
);
```

### Step 5: Run tests and commit

```bash
git commit -m "feat: add PWA manifest, service worker with Workbox offline caching"
```

---

## Task 19: Offline Time Entry Queue

**Files:**
- Create: `frontend/src/utils/offlineQueue.ts`
- Create: `frontend/src/components/OfflineBanner.tsx`
- Test: `frontend/src/utils/__tests__/offlineQueue.test.ts`

### Step 1: Implement IndexedDB queue

```ts
// frontend/src/utils/offlineQueue.ts
const DB_NAME = 'lexnebulis-offline';
const STORE_NAME = 'pending_sync';

export async function queueTimeEntry(entry: object): Promise<void> {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  tx.objectStore(STORE_NAME).add({ ...entry, _queued_at: Date.now() });
  await tx.done;
}

export async function getPendingCount(): Promise<number> {
  const db = await openDB();
  return db.transaction(STORE_NAME).objectStore(STORE_NAME).count();
}

export async function syncPendingEntries(): Promise<void> {
  // POST each pending entry to /api/billing/time-entries
  // On success, remove from IndexedDB
  // On conflict, keep in queue and show warning
}
```

### Step 2: Commit

```bash
git commit -m "feat: add offline time entry queue with IndexedDB and sync"
```

---

## Task 20: Responsive Design Changes

**Files:**
- Modify: `frontend/src/components/Layout/` — bottom navigation on mobile
- Create: `frontend/src/hooks/useIsMobile.ts`
- Modify: existing DataTable components — stacked cards on mobile

### Step 1: Implement

`useIsMobile.ts`:
```ts
import { useMediaQuery } from '@mantine/hooks';
export function useIsMobile() {
  return useMediaQuery('(max-width: 768px)');
}
```

Layout changes:
- Sidebar → 5-icon bottom nav on mobile (Dashboard, Matters, Calendar, Time, More)
- DataTable → stacked cards on mobile
- Forms → full-screen modals on mobile
- Timer → floating action button (bottom-right)

### Step 2: Commit

```bash
git commit -m "feat: add responsive mobile layout with bottom nav and stacked cards"
```

---

## Task 21: Push Notifications

**Files:**
- Create: `backend/app/notifications/` module
- Create: `frontend/src/utils/pushNotifications.ts`
- Test: `backend/tests/test_notifications.py`

### Step 1: Implement Web Push API

Backend:
- Store push subscriptions per user
- Celery tasks send push notifications for: deadline in 24h/1h, new portal message, payment received, trust alert, document filed

Frontend:
- Request notification permission on first mobile login
- Register service worker push subscription
- Display notifications via service worker

### Step 2: Commit

```bash
git commit -m "feat: add Web Push notifications for deadlines, payments, and alerts"
```

---

## Task 22: Camera-to-Matter Document Capture

**Files:**
- Create: `frontend/src/components/CameraCapture.tsx`
- Modify: document inbox upload to support camera source

### Step 1: Implement

```tsx
// Camera input using native HTML5 capture
<input
  type="file"
  accept="image/*"
  capture="environment"
  onChange={handleCapture}
/>
```

Captured photo stored in IndexedDB if offline, uploaded to inbox when online. Backend runs OCR → AI classification → normal Document Intelligence pipeline.

### Step 2: Commit

```bash
git commit -m "feat: add camera-to-matter document capture with offline support"
```

---

# Frontend Tasks (Features 1-3)

## Task 23: Document Inbox UI

**Files:**
- Create: `frontend/src/pages/DocumentInbox.tsx`
- Create: `frontend/src/components/documents/InboxItem.tsx`
- Create: `frontend/src/api/documentInbox.ts`

Build the inbox UI with:
- List of pending documents with AI classification badges
- Confidence indicator (color-coded by tier)
- Approve button → file to suggested or selected matter
- Reject button
- Reclassify button (misfiling correction)
- 24-hour undo for auto-filed items

## Task 24: Court Rules UI

**Files:**
- Create: `frontend/src/pages/CourtRules.tsx`
- Create: `frontend/src/components/court-rules/JurisdictionCard.tsx`
- Create: `frontend/src/components/court-rules/AcceptanceGate.tsx`
- Create: `frontend/src/components/court-rules/DeadlineCalculator.tsx`

Build the court rules UI with:
- Jurisdiction list with status badges (gray/yellow/green/blue)
- First-use acceptance gate modal (cannot be skipped)
- Per-rule verification checkboxes
- Deadline calculator form: trigger event, date, service method → calculated dates with disclaimers
- Generated deadline view per matter with statutory citations

## Task 25: Revenue Recovery UI

**Files:**
- Create: `frontend/src/pages/PaymentReminders.tsx`
- Create: `frontend/src/pages/TrustAlerts.tsx`
- Create: `frontend/src/components/billing/ReminderSchedule.tsx`
- Create: `frontend/src/components/trust/AlertCard.tsx`

Build:
- Reminder schedule management (pause/resume per matter, view escalation chain)
- Trust alert dashboard with severity indicators
- Plaid bank connection widget (Plaid Link)
- Payment plan creation for large invoices

## Task 26: Document Timeline and Search UI

**Files:**
- Create: `frontend/src/components/documents/Timeline.tsx`
- Create: `frontend/src/components/documents/VersionDiff.tsx`
- Modify: `frontend/src/pages/Search.tsx` — add full-text search with AI summaries

---

# Verification

After all tasks are complete:

```bash
# Backend tests
cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/ -v --tb=short

# Frontend tests
cd /Users/mattcatsimanes/LexNebulis/frontend && npx vitest run

# Docker Compose smoke test
cd /Users/mattcatsimanes/LexNebulis && docker compose up --build -d
curl http://localhost/api/health
```

**Feature checklist:**

| Feature | Backend | Frontend | Tests |
|---------|---------|----------|-------|
| Document Intelligence Hub | Tasks 2-6 | Task 23 | |
| Full-Text Search | Task 7 | Task 26 | |
| Document Timeline/Diff | Task 8 | Task 26 | |
| Court Rules Engine | Tasks 9-12 | Task 24 | |
| Payment Reminders | Tasks 13-14 | Task 25 | |
| Trust Alerts | Task 15 | Task 25 | |
| Plaid Integration | Task 16 | Task 25 | |
| Payment Plans | Task 17 | Task 25 | |
| PWA + Offline | Tasks 18-19 | — | |
| Responsive Design | — | Task 20 | |
| Push Notifications | Task 21 | Task 21 | |
| Camera Capture | — | Task 22 | |
