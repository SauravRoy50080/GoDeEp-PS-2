# Backend implementation roadmap

1. Evidence foundation (local intake implemented; accounts/sessions and case permissions implemented; deployment hardening pending): cases, samples, upload validation, hashes, audit records,
   authentication, authorization, database migrations and storage.
2. Jobs and adapters (queue and archive inventory implemented; malware engines pending): bounded workers, retries, cancellation, run provenance,
   raw output retention and normalized observations.
3. Static analysis: evaluate pinned engines using controlled test APKs.
4. Dynamic analysis: isolated Android environments, repeatable actions,
   filesystem/process/network observations and coverage reporting.
5. Intelligence and correlation: source-aware IoC enrichment, deduplication,
   explainable scoring and analyst review.
6. Reporting and AI: evidence-linked explanations, exports and investigation assistance.

At each stage evaluate false positives, category-level precision/recall and
coverage on controlled benign/malicious corpora. Do not promise accuracy before
benchmarking. No malware fixtures are included in Git.
