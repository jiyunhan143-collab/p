# Security Specification: 나의 ai 프롬프트 창고 (Admin Auth Hardened)

## 1. Data Invariants
1. **Admin-Only Writes**: All `create`, `update`, and `delete` operations on `/prompts/{promptId}` are strictly restricted to the verified Google account `jiyunhan143@gmail.com` (`request.auth != null && request.auth.token.email == 'jiyunhan143@gmail.com' && request.auth.token.email_verified == true`).
2. **Public Guest Read Access**: Unauthenticated guests can `get` and `list` `/prompts/{promptId}` to view, search, filter, and copy prompts.
3. **Strict Schema Enforcement**: Every document in `/prompts/{promptId}` MUST contain exactly `title`, `category`, `content`, and `createdAt` — no shadow fields allowed.
4. **Valid Document IDs**: Every `promptId` MUST match `^[a-zA-Z0-9_\-]+$` and be 1..128 chars.
5. **Category Allowlist**: `category` MUST be `'사진 합성'`, `'스타일 변환'`, or `'캐릭터·포스터'`.
6. **Volumetric Bounds**:
   - `title`: non-empty string, `1 <= size <= 120`
   - `content`: non-empty string, `1 <= size <= 20000`
7. **Temporal Integrity & Immutability**:
   - On `create`, `createdAt == request.time`.
   - On `update`, `createdAt == existing().createdAt` and only `['title', 'category', 'content']` may change.

## 2. Adversarial "Dirty Dozen" Payloads (Expected: PERMISSION_DENIED)
1. **Unauthenticated Create**: Guest calls `addDoc(collection(db, 'prompts'), ...)` -> Rejected by `isAdmin()`.
2. **Non-Admin Authenticated Create**: Signed-in user `other@gmail.com` calls `addDoc` -> Rejected by `email == 'jiyunhan143@gmail.com'`.
3. **Unverified Admin Email Spoof**: Token with `email: 'jiyunhan143@gmail.com'` and `email_verified: false` -> Rejected by `email_verified == true`.
4. **Unauthenticated Update/Delete**: Guest attempts `updateDoc` or `deleteDoc` -> Rejected by `isAdmin()`.
5. **Non-Admin Update/Delete**: Signed-in non-admin attempts `updateDoc` or `deleteDoc` -> Rejected by `isAdmin()`.
6. **Shadow Field Injection by Admin**: Payload includes extra field `isPinned: true` -> Rejected by `hasOnly`.
7. **Invalid Category Enum**: `category: "기타"` -> Rejected by `isValidCategory`.
8. **Oversized Title / Content**: `title` > 120 chars or `content` > 20,000 chars -> Rejected by `.size()` bounds.
9. **Forged Client Timestamp**: `createdAt` != `request.time` on create -> Rejected.
10. **Mutating `createdAt` on Update**: Updating `createdAt` -> Rejected by `incoming().createdAt == existing().createdAt`.
11. **Poisoned Document ID**: `prompts/bad id!` -> Rejected by `isValidId`.
12. **Unrecognized Collection Write**: Writing to `/admins/1` or `/users/1` -> Rejected by global default-deny rule.
