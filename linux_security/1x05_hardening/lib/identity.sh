#!/bin/bash

set_login_def() {
    local key="$1"
    local value="$2"

    if grep -Eq "^[[:space:]]*${key}[[:space:]]+" "$LOGIN_DEFS"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" "$LOGIN_DEFS"
    else
        printf '%s %s\n' "$key" "$value" >> "$LOGIN_DEFS"
    fi

    log "INFO" "Password policy $key set to $value"
}

configure_password_policy() {
    local pwquality_line

    pwquality_line="password requisite pam_pwquality.so retry=3 minlen=${PASS_MIN_LEN} ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"

    if grep -q "pam_pwquality.so" "$PAM_PASSWORD_FILE"; then
        sed -i -E "s|^[[:space:]]*password[[:space:]].*pam_pwquality\.so.*|${pwquality_line}|" "$PAM_PASSWORD_FILE"
    else
        sed -i "1i ${pwquality_line}" "$PAM_PASSWORD_FILE"
    fi

    set_login_def "PASS_MIN_LEN" "$PASS_MIN_LEN"
    set_login_def "PASS_MAX_DAYS" "$PASS_MAX_DAYS"

    log "INFO" "Password complexity policy configured"
}

configure_lockout_policy() {
    if grep -Eq "^[#[:space:]]*deny[[:space:]]*=" "$FAILLOCK_CONFIG"; then
        sed -i -E "s|^[#[:space:]]*deny[[:space:]]*=.*|deny = ${FAIL_LOCK_ATTEMPTS}|" "$FAILLOCK_CONFIG"
    else
        printf '\ndeny = %s\n' "$FAIL_LOCK_ATTEMPTS" >> "$FAILLOCK_CONFIG"
    fi

    if ! grep -q "pam_faillock.so preauth" "$PAM_AUTH_FILE"; then
        sed -i '1i auth required pam_faillock.so preauth silent' "$PAM_AUTH_FILE"
    fi

    if ! grep -q "pam_faillock.so authfail" "$PAM_AUTH_FILE"; then
        sed -i '/pam_deny.so/i auth [default=die] pam_faillock.so authfail' "$PAM_AUTH_FILE"
    fi

    if ! grep -q "pam_faillock.so" "$PAM_ACCOUNT_FILE"; then
        printf '\naccount required pam_faillock.so\n' >> "$PAM_ACCOUNT_FILE"
    fi

    log "INFO" "Account lockout configured after $FAIL_LOCK_ATTEMPTS failed attempts"
}

user_is_privileged() {
    local user="$1"
    local group

    for group in "${PRIVILEGED_GROUPS[@]}"; do
        if getent group "$group" >/dev/null 2>&1 && id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$group"; then
            return 0
        fi
    done

    return 1
}

user_is_excluded() {
    local user="$1"
    local excluded

    for excluded in "${CLEANUP_EXCLUDED_USERS[@]}"; do
        [ "$user" = "$excluded" ] && return 0
    done

    return 1
}

cleanup_users() {
    local user
    local uid

    while IFS=: read -r user _ uid _; do
        if [ "$uid" -gt "$CLEANUP_UID_THRESHOLD" ] && ! user_is_excluded "$user"; then
            if user_is_privileged "$user"; then
                log "INFO" "Preserved privileged user $user"
            else
                if userdel -r "$user" >/dev/null 2>&1; then
                    REMOVED_USERS+=("$user")
                    log "INFO" "Deleted non-compliant user $user with UID $uid"
                else
                    log "ERROR" "Failed to delete non-compliant user $user"
                    return 1
                fi
            fi
        fi
    done < "$PASSWD_FILE"
}

lock_root_password() {
    if passwd -S root | awk '{print $2}' | grep -Eq '^(L|LK)$'; then
        log "INFO" "Root password already locked"
    else
        if passwd -l root >/dev/null 2>&1; then
            log "INFO" "Root password locked"
        else
            log "ERROR" "Failed to lock root password"
            return 1
        fi
    fi
}

harden_identity() {
    configure_password_policy || return 1
    configure_lockout_policy || return 1
    cleanup_users || return 1
    lock_root_password || return 1

    log "INFO" "Identity hardening completed"
}
