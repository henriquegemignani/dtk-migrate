# Plan: recover PAL translation units from historical NTSC evidence

Status: living implementation plan. Change A landed through `0a351d2`; Change B landed at
`c6e0039`. The remaining plan below is based on the architecture after those changes.

## Implementation checkpoint after Change B

The objective, safety constraints and completion criteria still fit. Change B did, however, move
more groundwork into the observation layer than the original delivery order assumed:

- `IdentificationReport` is now the canonical function-attribution and TU-identification record.
  Change C must validate and index this report rather than derive a second attribution model from
  `MatchResult`, `CoverageUnit` or `TargetFunction`.
- Candidate sequences already carry section-local envelopes, target interiors and preliminary edge
  evidence. Change D should refine those records into address-bearing boundary hypotheses rather
  than introduce a parallel sequence model.
- The atomic transaction substrate from Change E should land after C and before D enables any new
  ownership-changing rule. Boundary inference can be developed diagnostically first, but accepted
  compositions should not be added to the legacy `Alternative`/`OwnerRevision` representation only
  to be rewritten immediately afterward.
- Transaction identity, before-state preconditions and stale-state regeneration belong to E. Change
  I then uses that identity for dependency-aware retry, diagnostics and caching.
- Known function attribution keeps a required source function and unit. Target-only helper/orphan
  evidence in G should use a separate deterministic cluster type rather than making every known
  attribution optional.

The full historical identification report is currently about 38 MB and the coverage report about
58 MB. G will add more helper and object evidence, so C should store the immutable observation
report once as a content-addressed run artifact. Prepared state, summaries and proposals should
refer to its digest and carry only the unit-local slice needed for a trial. Standalone
`match --identifications` output remains self-contained.

## Objective and measured starting point

Identify target translation units and recover their code/data ownership from the information available at an old project revision. Later source fixes and later target splits are evaluation answers, never inference inputs. Source compilation may supply additional evidence when available; matching source code is not a prerequisite for TU identification.

The historical experiment used Prime `b65ad2a6f9ae8e400e48f76209d3c015b22b84c0`, before the recent PAL work, migrating `GM8E01_00` to `GM8P01_00`. The comparison revision is `ca286f453d30c201304a82939fa8929181cc9d30`. Run `20713-150344` completed all four stages and reproduced retail. Its evidence is at:

`C:/Users/henri/programming/decomp/prime-migration-benchmark-b65ad2a6/build/dtk-migrate/runs/20713-150344/`

Of 35 newly PAL-linked TUs, 27 changed at least one split section and 25 changed `.text`. Published results were:

| Population | Exact | Partial or wrong | Unchanged despite needed correction |
|---|---:|---:|---:|
| 27 changed complete split bodies | 1 | 8 | 18 |
| 25 changed `.text` range sets | 2 | 6 | 17 |

Three of the eight already-correct complete split bodies were made wrong: `CGuiCamera`, `CFrameDelayedKiller`, and `CPlayerState`. `CGuiTableGroup` was recovered completely; `CStreamAudioManager` recovered `.text` but missed a `.bss` range. These counts combine partial and wrong outcomes because that is how the initial comparison was recorded; the new benchmark must distinguish them by address ownership.

The useful distinction is between identifying a TU, proving its boundaries, applying its changes, and verifying source linkage. Reporting an identified TU is necessary, but reporting alone does not satisfy boundary recovery. The implementation must improve actual proposals and safe application as well.

## Constraints to preserve

- A retail hash proves executable bytes, not TU ownership while extracted objects are linked.
- Function identity and linked ownership differ for weak/template/compiler-generated functions. A source-version owner is not automatically the target-version owner.
- Existing target splits and names are observations with provenance, not unquestionable boundaries.
- Unknown or contested ownership remains explicit. Never fill an unexplained gap merely because the bounding addresses are convenient.
- Every mutation carries complete replacement bodies, retains unrelated sections and attributes, and accounts for all owners affected.
- Workers evaluate assigned transactions. Rediscovery and reconciliation remain coordinator responsibilities.
- Publication and resume validate the final accepted evidence, including refinements and superseded certificates.
- No name-specific exceptions, PAL address constants, source fixes, or oracle paths enter the inference algorithm.

## 1. Add the historical regression benchmark before changing policy

**Files:** new `src/analysis/ownership_score.rs`, new `src/cli/benchmark.rs`, `src/cli/mod.rs`, `src/main.rs`, `src/cli/calibrate.rs`, new `tests/historical_recall.rs`, fixtures under `tests/fixtures/ownership/`.

Extract interval scoring from calibration into a shared library. Keep the existing calibration command and scenario semantics; have both calibration and historical evaluation use the same scorer. This is an extraction of scoring logic, not an opportunity to reinterpret how application works.

Add a read-only benchmark command with two explicit operations:

1. Prepare an oracle manifest from saved baseline/comparison metadata: revision IDs, retail digests, target split range sets, linkage changes and the evaluated population.
2. Score a completed run against that manifest. The scorer loads the inference output after the run, without providing the manifest to matching, workers, or injected evidence.

The manifest must use Git blobs or immutable saved files. The benchmark checkout was changed by publication, so its current `config/` is no longer the original baseline. Read that baseline from the recorded snapshot or baseline Git revision. Do not infer it from the post-run working tree.

Record separate fields for:

- Identification: absent, tentative, corroborated, or ambiguous; evidence and candidate target intervals.
- Proposal recall: whether any proposed transaction yields the exact answer, independently of which one was selected.
- Selection quality: exact, partial with no foreign bytes, wrong ownership, unknown territory, or no change.
- Application: not offered, not attempted, preflight refused, build refused, accepted, or superseded.
- Source verification: not attempted, failed, or verified.

Compare merged range sets per module/section, including multiple ranges in the same section. Report full-body and code-only accuracy separately, retain split attributes such as `align` and `common` for structural comparison, and distinguish semantic interval equality from formatting.

Measure correct bytes gained, previously correct bytes lost, newly wrong bytes, remaining wrong bytes, missed bytes, and bytes with no oracle answer. Score all changed owners and all touched unchanged controls. A neighbour harmed by another TU's acceptance counts against the transaction. Do not charge retained baseline errors as new errors, but do not hide them from the final state either.

The 35 recent TUs are a named recall set. The safety population must additionally cover every touched unit with trustworthy oracle ownership, especially already source-linked units. Later linked TUs are strong oracle cases; do not silently treat all unrelated, still-unmatched splits in current main as established truth.

**Tests and acceptance:** reproduce the existing 27/25 population counts and 1/2 exact counts; distinguish the truncated CameraPitchVolume result from Platform's foreign-byte theft; detect all three unchanged-control regressions; score multiple code/data ranges and a revised neighbour; prove moving or deleting the oracle cannot change inference output. Commit small metadata fixtures, not retail binaries. Retain an opt-in real-project test for the full run.

## 2. Separate observations, eligibility, and publication results

**Files:** `src/analysis/coverage.rs`, new `src/analysis/ownership.rs`, `src/matching/mod.rs`, `src/cli/match_cmd.rs`, `src/stages/coverage/mod.rs`, `src/stages/coverage/alternatives.rs`, `src/stages/mod.rs`.

Introduce typed records for function attribution and unit identification. Proposed shape:

```text
FunctionAttribution
  target module/section/address/extent
  source function and source unit, if known
  identity method, tier, ambiguity, weak/template status
  evidence references and origin

UnitIdentification
  source unit or unresolved cluster ID
  candidate target member sequences and envelopes
  identification confidence and competing explanations
  evidence references, missing members and unresolved helpers
  boundary blockers and application blockers
```

Generate these observations before applying byte thresholds, existing-owner overlap filters, `--only`, source-object availability, or build gates. Continue using the two retail binaries, source splits and baseline metadata as the core input. Expose the result through the existing read-only matching path so a project with uncompilable source still produces identifications. A migration may still require a buildable baseline for mutation.

An envelope is a hypothesis until both edges and intervening ownership are supported. Do not label a TU identified just because a single common helper has a match. Preserve competing hypotheses rather than collapsing them into a generic disposition.

Keep identification, boundary certainty, and application state as independent fields. A TU can be corroborated, have an unresolved edge, and have no safe application. `represented-and-unextendable` must no longer conceal whether the blocker was a small complete sequence, foreign ownership, ambiguity, or no new evidence. Report the complete inventory even when `--only` limits changes.

**Tests and acceptance:** historical Group and TransitionDatabase appear with their actual binary evidence even when automatic acceptance is refused; a build refusal retains the proposed boundary and identification; names-only hypotheses are distinguishable from independent corroboration; source/object files can be absent without losing binary identification.

## 3. Stop unsupported ownership growth

**Files:** new `src/analysis/ownership.rs`, `src/analysis/matching.rs`, `src/analysis/coverage.rs`, `src/stages/coverage/alternatives.rs`, `src/stages/coverage/mod.rs`, `src/analysis/unit_matching.rs`, `src/stages/discover.rs`.

Build a validated target-address attribution index from the complete `IdentificationReport`, not
just a candidate's selected functions. Key it by module, section and address, and keep attribution
IDs as the provenance carried into later boundary and transaction records. `TargetFunction` still
records current ownership but is not a second source of identity. Consequently an otherwise
plausible bounded sequence can no longer swallow foreign functions in the uncovered portion of its
gap.

Recompute aggregate counts, confidence, basis, candidate membership and edge references from the
underlying typed attributions when loading evidence. Referential integrity alone is insufficient:
serialized `eligible`, `independent`, count and confidence fields are diagnostics, not authority.
Store the validated immutable report once in the run and bind every derived proposal to its digest.

For every candidate, validate the full resulting range set and classify each covered function or interval as independently attributed to this TU, a supported helper, a conflicting attribution, padding, or unresolved. Distinguish problems already present in a retained block from newly introduced claims. A pre-existing questionable block must not prevent reporting a safe independent extension, but it prevents claiming complete certification of that body.

Reject an automatic new claim when it conflicts with corroborated, unique, non-shared function attribution. A high `MatchTier` alone is insufficient: `MatchMethod::Name` is currently automatically confident, and a name might have been supplied by a previous tool run. Store input-name versus same-run-derived-name provenance, and retain independent body, relocation, call and ambiguity evidence. Do not count a renamed symbol and the evidence that produced its name twice.

For weak/template functions, record an ownership conflict to resolve with helper evidence rather than applying an unconditional foreign-owner veto. A valid ownership-transfer transaction must explain who receives every removed interval and why. Shared helpers need the additional treatment in step 6.

Apply this check to boundary sequences, layout groups, composed ranges, exact-body fallback ranges and discovery proposals. Check again against the current transaction state before trial and against the final certificate at publication. All fallback alternatives must meet the gate; a blocked first choice must not expose an equally bad fallback.

Change ranking so complete corroborated membership, supported edges and absence of unexplained/foreign members precede range size. Bytes gained can break ties among equally supported choices. Claiming more bytes is not stronger evidence. Compare materially conflicting proposals before picking a winner; unresolved competition must not be decided by batch or unit order.

**Tests and acceptance:** a Platform-shaped sequence cannot take Sound's tail; PlayerState cannot take Timer's constructor/helper cluster on gap size alone; a weak function legitimately emitted by a different target TU is not automatically misclassified; forged `eligible` or aggregate counts cannot bypass validation. Evaluate every retained fallback against the historical oracle, including the known ScriptLoader false fragment.

## 4. Generate independent edges and recover small complete sequences

**Files:** `src/analysis/coverage.rs`, new `src/analysis/boundaries.rs`, `src/stages/coverage/alternatives.rs`, shared coverage policy definitions.

Replace the assumption that a boundary sequence owns the entire current-neighbour gap. Preserve that gap as a search window. Derive member sequences and candidate left/right edges from matched function extents, exact/layout groups, independently identified neighbours, relocations and supported helpers.

Extend the existing `CandidateSequence`/`EdgeEvidence` observations into boundary hypotheses. Each
edge needs its address, evidence references, competing addresses and dependence on current
ownership. Compose a left edge from one evidence family and a right edge from another only when
they describe the same unit/module/section, have compatible member sequences, and pass the full
interior-attribution check. Reject compositions that span an unrelated island. Inference must
support `.init` as well as `.text`; remove current `.text` restrictions only when the same checks
operate on section-local members.

Platform is the concrete composition case: layout evidence supplies start `0x800AA344`, while sequence evidence supplies end `0x800AD964`. Keep both original alternatives for diagnosis, but offer the corroborated composition ahead of incomplete choices once its interior and edges pass.

Add a complete-sequence policy route that does not require 512 aligned bytes. Require known extents, an unambiguous ordered pairing, independently supported edges, no unexplained interior function or foreign claim, and corroboration not based solely on weak functions. Account for version-specific inserted/deleted functions explicitly; matching all source members alone does not mean every target member has been explained.

The first enabled small-sequence case should be Group: six of six members, full target coverage,
four independently supported members. Its current observation still has unresolved adjacent edges
and a helper, so the rule must show how the complete sequence resolves those facts rather than
ignoring their blockers. Do not lower the global minimum to make BlockInstruction or three-function
text classes pass. Their stale edges, generated helpers, or missing independent evidence require the
corresponding mechanisms below. TransitionDatabase's 24/24 alignment is currently a tentative,
name-and-helper-heavy hypothesis: it has binary evidence but no independently supported non-helper
member. Automatic ownership must wait for independent call/relocation/vtable or object
corroboration and accounting for its extra target functions.

Move policy constants into one shared policy module used by generation and validation. `current_policy()` centralizes report construction, but `alternatives.rs` still duplicates thresholds and `matched_sequence()` mainly checks structure after trusting `eligible`. Validate serialized evidence against the same declared policy without trusting its summary booleans or counts.

**Tests and acceptance:** recover Group's full range; create Platform's exact composed range; do not bridge an unrelated gap; refuse a complete but ambiguous sequence; preserve secondary code sections; a full source sequence with unexplained target functions remains unresolved. Run all existing calibration scenarios before enabling the rule.

## 5. Introduce atomic ownership transactions, then solve neighbouring TUs

**Files:** new `src/analysis/unit_runs.rs`, `src/analysis/unit_matching.rs`, `src/analysis/coverage.rs`, `src/stages/coverage/alternatives.rs`, `src/stages/coverage/mod.rs`, `src/stages/mod.rs`, `src/run/mod.rs`, `src/run/jobs.rs`, `src/run/publish.rs`, `src/project/link_order.rs`.

The current `windows(3)` generator requires useful target boundaries for both immediate source neighbours. Replace it incrementally with run inference between independently supported outer anchors. Already represented but suspect units belong in the run too. Current target ownership constrains the required edits; it does not define the correct answer.

Construct candidate cuts at function boundaries and supported alignment padding. Label candidate intervals with unit evidence from steps 2–4. Use a bounded dynamic program or equivalent graph search over target cuts and source-unit order:

1. Hard-reject foreign attributed members, illegal cuts, overlap and unsupported ownership loss.
2. Permit an explicit unknown interval and unmatched source unit so the solver never has to force a partition.
3. Rank coherent member/edge evidence before explained bytes; record the best competing partition and evidence overlap.
4. Automatically select only a decisive partition. Equal plausible partitions remain ambiguous.

Bound the search by candidate cuts, competing hypotheses and work budget, and report exhaustion. Do not hard-code three-unit runs. Reuse `unit_matching.rs` grouping/attribution where it is valid rather than maintaining two inconsistent models. Source order is a hypothesis that can be interrupted by independently proven reordered units; do not force cross-version order through a contradictory anchor.

Introduce this typed ownership transaction before enabling Change D's new composition rule. It
contains all affected unit bodies, exact before-state preconditions, evidence references, transfers,
expected read/write sets and the digest of the observation/policy state that produced it. Preserve
unmodified ranges and split attributes. Existing `OwnerRevision` supports only narrowing one
contiguous section; it is insufficient for general swaps, multiple ranges, or simultaneous
extensions. Generalize through one shared atomic apply function used by calibration, trials and
publication. Construct and validate the changed map before committing it so errors never leave
partial mutations.

Validate that transferred intervals have a justified receiver, unrelated ownership is preserved, code/data ranges do not overlap, and link order remains acyclic. Allow a correction with zero net byte gain or a justified shrink; `complete()` currently drops anything without positive growth. Growth stays a metric, not eligibility.

Give a transaction its own stable ID over its canonical full after-state, exact before-state,
required extracts, evidence digest, policy digest and explicit member list. One multi-owner
transaction is one worker job item, never several independently accepted unit candidates. Schedule
transactions with overlapping read/write sets in a conflict component; trial dependent changes
together. At integration, stale before-state preconditions trigger regeneration, not silent
application. Expand final reporting back to per-unit effects while retaining the transaction
identity. A group may mutate only permitted units: if `--only` excludes a required neighbour,
report the dependency and refuse that mutation.

**Tests and acceptance:** recover Sound/Platform jointly; represent the Pane/Slider and Group/Head/Light problems as coupled hypotheses; a conflict cannot depend on worker completion order; a failed group restores every file and owner; equal-size boundary correction is offered; full coordinator tests cover group acceptance, later refinement, publication, interruption/resume and `--only` constraints.

## 6. Model helpers and optional compiled-object corroboration

**Files:** new `src/analysis/helpers.rs`, new `src/analysis/object_evidence.rs`, `src/derive/objects.rs`, `src/derive/body.rs`, `src/derive/ordering.rs`, `src/analysis/callgraph.rs`, `src/analysis/data_matching.rs`, `src/analysis/coverage.rs`.

Start with binary evidence. Build families for duplicate normalized bodies and weak/template/generated functions rather than forcing a unique source owner. Record available defining units, call/relocation relationships, vtable slots, constructor/destructor relationships, nearby attributed functions and ambiguity. A sole caller or a shared class name is supporting evidence, not proof of linker ownership.

Attach a helper only when independent boundary/ordering evidence resolves its emitted owner. Several units may compile the same helper while only one target unit emits it; keep definition availability separate from emitted ownership. Do not recover deleted/inlined helpers merely to force source and target counts to agree.

Add compiled source objects as an optional second channel using the existing object readers and body/order comparison code. Read `base_path` for compiled source and `target_path` for extracted retail objects. Inspect the complete compiled object, including locals, weak symbols, generated functions, non-code symbols and relocations. Search plausible target windows beyond the currently extracted split; restricting comparison to a truncated extracted object reproduces the original blind spot.

A mismatching object is still useful member evidence. Compiler flags or source differences may change emitted order and helper presence, so object agreement corroborates identity; disagreement does not erase independently supported binary identification. Cache by object digest, target binary digest and policy, and record compiler/configuration provenance. Missing objects should yield an unavailable evidence channel, not a failed identification run.

When a cluster has no baseline source TU, emit a separate `UnresolvedTargetCluster` (or equivalent)
with a deterministic ID and supported type/symbol clues. Do not weaken `FunctionAttribution` by
making its known source optional, invent a filename or assign the cluster to its nearest represented
neighbour. `CTimeRemainderAndFraction.cpp` was introduced later; success at the historical baseline
is detecting and bounding its separate cluster, not predicting that exact future path. A later
explicit user mapping or independently grounded unit identity can resolve it.

**Tests and acceptance:** compiler-generated text-instruction tails are represented as helper hypotheses; small widget type-ID functions get ownership through supporting unit evidence; duplicate helper definitions remain ambiguous when linker ownership is unproven; the CTime cluster is not swallowed by FrameDelayedKiller; binary-only mode still identifies supported units when every compiled object is removed.

## 7. Recover data ranges and permit safe later stages on the same TU

**Files:** `src/analysis/data_matching.rs`, `src/analysis/unit_matching.rs`, `src/stages/discover.rs`, `src/stages/coverage/extracts.rs`, `src/stages/coverage/mod.rs`, `src/stages/mod.rs`, `src/cli/run.rs`, `src/run/mod.rs`, `src/run/publish.rs`.

Use matched relocations and object symbol inventories to recover non-code membership. BSS has no distinctive bytes; require symbol/relocation/size/alignment/ownership evidence instead of byte matching. Preserve multiple ranges in a section, particularly ordinary `.bss` plus common BSS. Replace min-start/max-end merging where it spans unrelated allocations, and treat source-version sizes as bounds or priors rather than proof of an unowned tail.

Combine compatible code and data edits into one complete transaction when their evidence is available together. Retain an explicit unresolved-data state when only code is known. Existing discovery chooses a code candidate instead of its data candidate for the same TU; that should no longer postpone proven data merely because code was also offered.

Replace the global `BTreeSet<String>` reservation with typed mutation scopes and certificates. Derive candidates use symbol names while other stages use unit names; they should not share an untyped namespace. A coverage acceptance may constrain a TU's code ranges while permitting a proven data addition or source-link verification.

This needs corresponding publication changes, not just removal of reservations. Coverage currently requires its saved full block to be unchanged and its source object to remain excluded. Introduce separate checks for ownership evidence, trial linkage mode, and final source-link proof. A later verify certificate may legitimately supersede the extracted-input condition while retaining ownership evidence. A later data edit refreshes the complete final body without invalidating an unchanged code claim. If ownership itself changes, invalidate and re-prove dependent claims and source verification.

Maintain a final per-unit ownership state and certificate dependency graph. Publish and resume validate the composed final state rather than replaying incompatible historical predicates. Preserve the original evidence and supersession chain for audit.

**Tests and acceptance:** coverage → data completion → verify for one TU can finish in a single run; StreamAudioManager's two BSS ranges are retained; a symbol rename cannot accidentally reserve an identically named unit; changing code after verification invalidates its certificate; interruption between stages resumes with identical final certificates and no lost sections.

## 8. Make refusals diagnostic and retries state-aware

**Files:** `src/build/process.rs`, `src/build/context.rs`, `src/stages/mod.rs`, `src/stages/coverage/mod.rs`, `src/stages/discover.rs`, `src/stages/verify.rs`, `src/run/mod.rs`, `src/run/jobs.rs`.

Extend command failures with command identity, log path/offset range and a bounded stdout/stderr excerpt. `CommandError::Failed` currently retains only an exit status; `failure_category()` cannot detect undefined symbols or overlaps from that. Classify from the failed command's output, not the tail of a cumulative log that may belong to another trial. Preserve raw evidence even if classification is unknown.

Use structured refusal kinds: conflicting attribution, illegal split, link-order cycle, undefined symbol, source compile error, retail mismatch, measured regression, timeout, unavailable input and stale precondition. A failure's affected symbols/units should be recorded when extractable. Cancellation and infrastructure failures continue to stop a run rather than condemning a candidate.

Do not assume Pane's earlier undefined animation symbols prove an unrelated failure. Reproduce its oracle-exact proposal on the untouched historical baseline and compare the failed command inputs to determine whether it is an interaction, hidden split dependency, or tooling problem. Keep it classified as identified/proposed but application-refused until measured.

Key retry decisions by the transaction identity introduced in E plus relevant dependency state, not
only candidate name or alternative range ID. Permit a retry after a relevant neighbour or dependency
changes, and suppress identical repeated work on an unchanged state. Do not invalidate all retries
for unrelated workspace edits.

Retain coordinator-only rediscovery. Report attempted, skipped-as-unchanged, regenerated and budget-exhausted counts separately. Reuse binary/function matching when only ownership changes; invalidate ownership-derived windows and proposal construction without recomputing immutable fingerprints. Optimize after correctness tests exist.

**Tests and acceptance:** failures in adjacent trials cannot borrow each other's diagnostics; the same proposal is retried after a relevant dependency repair; an unrelated change does not cause a retry; no-candidate and all-refused baseline runs still succeed; the A → B → A cascade still publishes and resumes correctly.

## 9. Compatibility, reporting and documentation (continuous)

**Files:** `src/analysis/coverage.rs` and shared policy module, `src/stages/coverage/mod.rs`, `src/run/mod.rs`, `src/analysis/coverage_fixture.rs`, `tests/cascade.rs`, `README.md`, `docs/coverage.md`, `docs/runs.md`, `docs/prime.md`.

Version the new evidence records and transaction/certificate storage explicitly. Reject incompatible resumptions with a clear explanation; do not deserialize missing attribution or precondition fields as if they passed the new safety checks. Keep a read-only legacy-result adapter for scoring run `20713-150344`, whose migration schema must remain immutable.

Separate schema versions from policy versions. Bump policy whenever acceptance semantics change, even when the JSON shape does not. Include module/section identities in address keys and hashes so future REL or multi-section support cannot collide on an address.

Update the stale policy-8 documentation, statements that represented units cannot be candidates, and wording implying a retail build settles ownership. Document the four distinct results: identification, boundary recovery, applied ownership and verified source linkage. Reports should link every identified but unresolved TU to its concrete blockers and competing hypotheses.

## Delivery order and review boundaries

Each change should be reviewable and tested locally. The plan does not require one large rewrite before measuring progress.

| Change | Deliverable | Dependencies |
|---|---|---|
| A | Shared scoring, immutable historical manifest, regression fixtures | None |
| B | Typed attribution, source-independent identification output, persisted blockers | A |
| C | Full-range conflict validation, provenance, safe ranking and fallback validation | B |
| E | Atomic ownership transaction, identity and coordinator/publication integration | A–C |
| D | Independent edges, composition, conservative small complete-sequence rule | C, E before enabling policy |
| F | Joint run inference using atomic transactions | D, E |
| G | Binary helper families, optional object corroboration, orphan clusters | B–D; E for transfers |
| H | Data range recovery and scoped cross-stage certificates | E, G |
| I | Dependency-aware retries, caching and final full validation | E–H |

Schema and documentation changes accompany the change that needs them. B's identification blocker
reporting is complete; structured command/build failure diagnostics remain in I. C should land
before any recall-expanding rule. Boundary hypotheses from D may be developed before E, but no new
ownership-changing policy should be enabled until transactions are in place. G can be developed
independently of the joint solver once the attribution model is stable.

## Validation and completion criteria

For each inference change, run its targeted counterexample tests, all five hidden-ownership calibration scenarios, and the historical proposal scorer. Broader checks should follow semantic changes, not be repeated after documentation-only edits. At integration checkpoints run `cargo fmt --check`, `cargo clippy --all-targets`, the existing unit/cascade/pipeline suites, and the opt-in real-project suite.

Before accepting the complete implementation, rerun the historical migration from a fresh immutable baseline with the same toolchain. Also evaluate a second historical cutoff and a held-out version pair; do not tune rules until they happen to fit these 35 PAL TUs. Check binary-only inference, optional object inference, normal baseline names and hidden target names separately. Name removal will reduce available evidence; report that loss honestly rather than promising identical recall.

Required outcomes:

1. No newly wrong known ownership or loss of previously correct ownership in the benchmark safety population. The three unchanged-control regressions must disappear.
2. Every baseline-existing TU in the recent set receives an explicit evidence-backed identification assessment. A generic missing/unextendable label is not sufficient. Any unresolved identity must name its competing evidence and missing discriminator.
3. Group, TableGroup and the compatible Platform/Sound edges are exactly recoverable from historical evidence; the relevant test cases must assert boundary addresses, not nonempty candidate lists.
4. Consecutive-unit and helper cases produce actual recovery transactions when evidence resolves them, and atomic trials preserve every neighbour. Ambiguity remains an explicit unresolved outcome.
5. StreamAudioManager's code and multiple BSS ranges can complete in one run when supported; source verification is attempted where old source permits it, without being used as the identification denominator.
6. The later CTime TU is accounted for as a separate supported cluster if the baseline provides no trustworthy filename. Do not count inability to predict a future path as failed binary identification.
7. Published outcomes, stored selections, final certificates and resumed outcomes agree exactly. A result marked accepted cannot conceal an unsafe fallback or an unscored owner revision.
8. Final report compares exact, partial, wrong, unknown and missed results against the initial run, with per-TU reasons and runtime/build counts. Any remaining miss is tied to a specific evidence limitation or unimplemented mechanism, not blamed on absent later source fixes.

The goal is automatic recovery wherever the available evidence resolves ownership. A higher count of reported hypotheses is useful progress, but is not a replacement for improved exact-boundary recall.
