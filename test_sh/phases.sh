# 辰星认证中枢 - 测试运行器阶段实现
#
# 本文件由 test_sh/test.sh source，不单独执行，因此没有 shebang。
#
# 约定（重要）：
#   - 每个 phase_* 只做一件事，从全局变量读配置，用 record 写结果。
#   - 任何 phase_* 都不得 exit。一次运行要把所有问题一次报完，
#     最终退出码由 test.sh 依据汇总表统一决定。
#   - 工具缺失只有在该阶段被明确请求（或由 --gate 强制请求）时才允许
#     继续；此时必须记 fail，避免 false-green。未请求的可选阶段才记 skip。

# ---------------------------------------------------------------- 格式检查
phase_fmt() {
    local begin log status
    begin="$(now_ms)"
    log="$LOG_DIR/fmt.log"

    spinner_start "cargo fmt --check"
    cargo fmt --all -- --check >"$log" 2>&1
    status=$?
    spinner_stop

    if [ "$status" -eq 0 ]; then
        record "格式检查" ok "$(( $(now_ms) - begin ))"
        return 0
    fi
    record "格式检查" fail "$(( $(now_ms) - begin ))" "运行 cargo fmt --all 修复"
    err "格式不合规，以下文件需要 cargo fmt --all："
    grep -E '^Diff in ' "$log" | sed 's/^Diff in /  /' | sort -u | head -n 30
    return 0
}

# ---------------------------------------------------------------- 编译
# 单独编译一次拿到 Cargo 的产物清单（compiler-artifact JSON）。这份清单是
# 「哪些二进制还活着」的权威依据，剪枝阶段据此精确删除陈旧配置的残留。
# nextest 随后的编译命中同一批 fingerprint，只做校验，不重复编译。
phase_build() {
    local begin status
    begin="$(now_ms)"

    spinner_start "编译测试目标"
    cargo test --no-run --quiet --message-format json-render-diagnostics \
        "${CARGO_SCOPE[@]}" >"$LIVE_FILE" 2>"$LOG_DIR/build.log"
    status=$?
    spinner_stop

    if [ "$status" -eq 0 ]; then
        BUILD_OK=1
        record "编译" ok "$(( $(now_ms) - begin ))"
        return 0
    fi
    BUILD_OK=0
    record "编译" fail "$(( $(now_ms) - begin ))" "见 $LOG_DIR/build.log"
    err "编译失败："
    show_diagnostics "$LOG_DIR/build.log" 200
    return 0
}

# ---------------------------------------------------------------- 运行测试
phase_test() {
    local begin log status elapsed summary_line target
    begin="$(now_ms)"
    log="$LOG_DIR/test.log"

    info "测试期间通过用例保持静默；下方计时持续变化即仍在运行"
    spinner_start "运行测试"

    if [ -n "$FILTER_EXPR" ] && [ "$NEXTEST" -eq 0 ]; then
        spinner_stop
        record "测试" fail "$(( $(now_ms) - begin ))" "--filter 需要 cargo-nextest，不能回退到未过滤 cargo test"
        err "--filter 需要 cargo-nextest；为避免改变测试范围，已拒绝执行回退命令"
        return 0
    fi

    if [ "$NEXTEST" -eq 1 ]; then
        local args=(run --all-features --no-pager --max-fail "$MAX_FAIL")
        # 关键的安静开关：通过的用例既不打状态行也不打输出，只有失败会显示。
        args+=(--status-level fail --final-status-level fail)
        args+=(--success-output never --failure-output final)
        [ "$ONLY_LIB" -eq 1 ] && args+=(--lib)
        if [ "${#TEST_TARGETS[@]}" -gt 0 ]; then
            for target in "${TEST_TARGETS[@]}"; do args+=(--test "$target"); done
        fi
        [ -n "$FILTER_EXPR" ] && args+=(-E "$FILTER_EXPR")
        [ -n "$JOBS" ] && args+=(-j "$JOBS")

        cargo nextest "${args[@]}" >"$log" 2>&1
        status=$?
    else
        warn "未安装 cargo-nextest，回退到 cargo test（无法过滤通过用例的输出）"
        local fallback=(--all-features)
        [ "$ONLY_LIB" -eq 1 ] && fallback+=(--lib)
        if [ "${#TEST_TARGETS[@]}" -gt 0 ]; then
            for target in "${TEST_TARGETS[@]}"; do fallback+=(--test "$target"); done
        fi
        cargo test --quiet "${fallback[@]}" >"$log" 2>&1
        status=$?
    fi
    spinner_stop

    elapsed="$(( $(now_ms) - begin ))"
    summary_line="$(grep -aE '^[[:space:]]*Summary' "$log" 2>/dev/null | tail -1 \
        | sed -e 's/\x1b\[[0-9;]*m//g' -e 's/^[[:space:]]*Summary[[:space:]]*//' || true)"
    [ -z "$summary_line" ] && summary_line="$(grep -aE '^test result:' "$log" 2>/dev/null \
        | tail -1 | sed 's/^test result: //' || true)"

    if [ "$status" -eq 0 ]; then
        record "测试" ok "$elapsed" "${summary_line:-全部通过}"
        return 0
    fi

    record "测试" fail "$elapsed" "${summary_line:-见 $log}"
    err "测试失败："
    # nextest 的 --failure-output final 已把失败输出集中在末尾，直接透传。
    if [ "$VERBOSE" -eq 1 ]; then
        sed 's/\x1b\[[0-9;]*m//g' "$log"
    else
        awk '/(^|[[:space:]])(FAIL|TRY [0-9]+ FAIL|SIGSEGV|TIMEOUT|LEAK)[[:space:]]/,0' "$log" \
            | sed 's/\x1b\[[0-9;]*m//g' | head -n 400
        [ "$(wc -l <"$log")" -gt 400 ] && printf '  %b完整日志：%s%b\n' "$DIM" "$log" "$RESET"
    fi
    return 0
}

# ---------------------------------------------------------------- 静态检查
phase_clippy() {
    local begin log status
    begin="$(now_ms)"
    log="$LOG_DIR/clippy.log"

    spinner_start "cargo clippy"
    cargo clippy --all-targets --all-features --quiet -- -D warnings >"$log" 2>&1
    status=$?
    spinner_stop

    if [ "$status" -eq 0 ]; then
        record "静态检查" ok "$(( $(now_ms) - begin ))"
        return 0
    fi
    record "静态检查" fail "$(( $(now_ms) - begin ))" "见 $log"
    err "clippy 有告警："
    show_diagnostics "$log" 200
    return 0
}

phase_check_all() {
    local begin log status
    begin="$(now_ms)"
    log="$LOG_DIR/check.log"

    spinner_start "cargo check --all-targets"
    cargo check --all-targets --all-features >"$log" 2>&1
    status=$?
    spinner_stop

    if [ "$status" -eq 0 ]; then
        record "全量检查" ok "$(( $(now_ms) - begin ))"
        return 0
    fi
    record "全量检查" fail "$(( $(now_ms) - begin ))" "见 $log"
    err "cargo check 失败："
    show_diagnostics "$log" 200
    return 0
}

# ---------------------------------------------------------------- 覆盖率
# lcov.info 里 LF/LH 是每个文件的可执行行数与命中行数，累加即整体行覆盖率。
coverage_percent() {
    [ -f lcov.info ] || return 0
    awk -F: '
        $1 == "LF" { total += $2 }
        $1 == "LH" { hit += $2 }
        END { if (total > 0) printf "%.2f", hit * 100 / total }
    ' lcov.info
}

# cargo-llvm-cov 用独立的 target/llvm-cov-target，从零重编一整套测试二进制，
# 磁盘占用基本翻倍。对抗 target 膨胀是这个工具存在的理由，所以顺手剪掉它。
# 该目录不是本次 cargo test 的产物，没有权威 live 清单，只能 heuristic。
prune_coverage_target() {
    local dir="target/llvm-cov-target" log="$LOG_DIR/prune-coverage.log" result freed
    [ -d "$dir" ] || return 0
    local args=(--target-dir "$dir" --profile debug --mode heuristic --repo-root "$REPO_ROOT")
    [ "$DRY_RUN" -eq 1 ] && args+=(--dry-run)
    python3 test_sh/prune_target.py "${args[@]}" >"$log" 2>&1 || return 0
    result="$(grep -m1 '^RESULT ' "$log" 2>/dev/null || true)"
    [ -n "$result" ] || return 0
    freed="$(printf '%s' "$result" | sed -n 's/.*freed=\([0-9]*\).*/\1/p')"
    [ -n "$freed" ] || return 0
    human_size "$freed"
}

phase_coverage() {
    local begin log status percent freed note
    begin="$(now_ms)"

    if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
        if [ "$MODE" = "coverage" ] || [ "$MODE" = "gate" ]; then
            record "覆盖检查" fail 0 "未安装 cargo-llvm-cov"
            err "覆盖检查被请求但 cargo-llvm-cov 不可用"
        else
            record "覆盖检查" skip 0 "未安装 cargo-llvm-cov"
        fi
        return 0
    fi

    log="$LOG_DIR/coverage.log"
    spinner_start "cargo llvm-cov"
    cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info \
        --fail-under-lines 75 >"$log" 2>&1
    status=$?
    spinner_stop

    percent="$(coverage_percent)"
    freed="$(prune_coverage_target)"
    note="行覆盖 ${percent:-未知}%（门槛 75%）"
    [ -n "$freed" ] && note="$note，覆盖率 target 释放 $freed"

    if [ "$status" -eq 0 ]; then
        record "覆盖检查" ok "$(( $(now_ms) - begin ))" "$note"
        return 0
    fi
    record "覆盖检查" fail "$(( $(now_ms) - begin ))" "$note，见 $log"
    err "覆盖率门槛未通过："
    grep -aiE 'error|warning: .*coverage|the required|fail-under' "$log" | tail -n 20
    return 0
}

# ---------------------------------------------------------------- 依赖审计
phase_audit() {
    local begin log status note
    begin="$(now_ms)"

    if ! command -v cargo-audit >/dev/null 2>&1; then
        if [ "$MODE" = "audit" ] || [ "$MODE" = "gate" ]; then
            record "依赖审计" fail 0 "未安装 cargo-audit"
            err "依赖审计被请求但 cargo-audit 不可用"
        else
            record "依赖审计" skip 0 "未安装 cargo-audit"
        fi
        return 0
    fi

    log="$LOG_DIR/audit.log"
    spinner_start "cargo audit"
    # RUSTSEC-2023-0071 目前没有修复版本：它经 webauthn-rs -> crypto-glue -> rsa
    # 引入，本项目不用该依赖做 RSA 私钥解密/签名。上游修复后删掉这个 ignore。
    # 与 .github/workflows/ci.yml 保持一致，本地和 CI 不能有两套判定。
    cargo audit --ignore RUSTSEC-2023-0071 >"$log" 2>&1
    status=$?
    spinner_stop

    note="已忽略 RUSTSEC-2023-0071"
    if [ "$status" -eq 0 ]; then
        record "依赖审计" ok "$(( $(now_ms) - begin ))" "$note"
        return 0
    fi
    record "依赖审计" fail "$(( $(now_ms) - begin ))" "$note，见 $log"
    err "依赖审计发现问题："
    grep -aE '^(Crate|Warning|ID|Severity|Title|Solution|error)' "$log" | head -n 40
    return 0
}

# ---------------------------------------------------------------- 源文件行数
# 与 ci.yml 的 "Check Rust source file size" 同一套判定：
# 超过 500 行是强警告（失败），超过 300 行是弱警告（只记数）。
phase_src_limit() {
    local begin log file lines hard=0 soft=0
    begin="$(now_ms)"
    log="$LOG_DIR/src-limit.log"
    : >"$log"

    while IFS= read -r -d '' file; do
        lines="$(wc -l <"$file")"
        if [ "$lines" -gt 500 ]; then
            printf '超过 500 行（必须拆分）：%s（%s 行）\n' "$file" "$lines" >>"$log"
            hard=$((hard + 1))
        elif [ "$lines" -gt 300 ]; then
            printf '超过 300 行（弱警告）：%s（%s 行）\n' "$file" "$lines" >>"$log"
            soft=$((soft + 1))
        fi
    done < <(find src -type f -print0)

    local note="${hard} 个超 500 行，${soft} 个超 300 行"
    if [ "$hard" -eq 0 ]; then
        record "行数检查" ok "$(( $(now_ms) - begin ))" "$note"
        [ "$soft" -gt 0 ] && [ "$VERBOSE" -eq 1 ] && grep '弱警告' "$log"
        return 0
    fi
    record "行数检查" fail "$(( $(now_ms) - begin ))" "$note"
    err "以下源文件超过 500 行，必须拆分："
    grep '必须拆分' "$log" | head -n 30
    return 0
}

# ---------------------------------------------------------------- 剪枝清理
# 读全局：PRUNE_MODE / LIVE_FILE / DEEP_CLEAN / DRY_RUN / VERBOSE / REPO_ROOT
phase_prune() {
    local begin log status result deleted freed target_size note
    begin="$(now_ms)"
    log="$LOG_DIR/prune.log"

    local args=(--target-dir target --profile debug --repo-root "$REPO_ROOT" --mode "$PRUNE_MODE")
    # exact 需要本次编译的权威产物清单；清单不存在时降级，绝不硬跑 exact。
    if [ "$PRUNE_MODE" = "exact" ] && [ -s "$LIVE_FILE" ]; then
        args+=(--live-file "$LIVE_FILE")
    elif [ "$PRUNE_MODE" = "exact" ]; then
        args=(--target-dir target --profile debug --repo-root "$REPO_ROOT" --mode heuristic)
    fi
    [ "$DEEP_CLEAN" -eq 1 ] && args+=(--deep)
    [ "$DRY_RUN" -eq 1 ] && args+=(--dry-run)
    [ "$VERBOSE" -eq 1 ] && args+=(--verbose)

    spinner_start "清理陈旧产物"
    python3 test_sh/prune_target.py "${args[@]}" >"$log" 2>&1
    status=$?
    spinner_stop

    result="$(grep -m1 '^RESULT ' "$log" 2>/dev/null || true)"
    if [ "$status" -ne 0 ] || [ -z "$result" ]; then
        warn "清理未完成，详见 $log"
        record "清理产物" fail "$(( $(now_ms) - begin ))" "见 $log"
        return 0
    fi

    deleted="$(printf '%s' "$result" | sed -n 's/.*deleted=\([0-9]*\).*/\1/p')"
    freed="$(printf '%s' "$result" | sed -n 's/.*freed=\([0-9]*\).*/\1/p')"
    target_size="$(printf '%s' "$result" | sed -n 's/.*target=\([0-9]*\).*/\1/p')"

    [ "$VERBOSE" -eq 1 ] && grep -v '^RESULT ' "$log"

    note="删除 ${deleted} 项，释放 $(human_size "$freed")，target 现 $(human_size "$target_size")"
    [ "$DRY_RUN" -eq 1 ] && note="[dry-run] $note"
    record "清理产物" ok "$(( $(now_ms) - begin ))" "$note"

    # 30 GiB 以上说明还有别的堆积，给出根因提示而不是默默忍受。
    if [ "${target_size:-0}" -gt $((30 * 1024 * 1024 * 1024)) ]; then
        warn "target 仍超过 30 GiB。单个测试二进制约 242 MiB，主要是调试信息；"
        warn "可用 --deep-clean，或在 Cargo.toml 给 [profile.test] 设 debug=\"line-tables-only\""
    fi
    return 0
}
