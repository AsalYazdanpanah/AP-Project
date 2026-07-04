#include <bits/stdc++.h>
using namespace std;

class SHA256 {
    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static string toHex(const vector<unsigned char>& bytes) {
        static const char* hex = "0123456789abcdef";
        string out;
        out.reserve(bytes.size() * 2);
        for (unsigned char b : bytes) {
            out.push_back(hex[b >> 4]);
            out.push_back(hex[b & 15]);
        }
        return out;
    }
public:
    static string hash(const string& input) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        uint32_t h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        vector<unsigned char> data(input.begin(), input.end());
        uint64_t bitLen = (uint64_t)data.size() * 8ULL;
        data.push_back(0x80);
        while ((data.size() % 64) != 56) data.push_back(0);
        for (int i = 7; i >= 0; --i) data.push_back((unsigned char)((bitLen >> (8 * i)) & 0xff));

        for (size_t offset = 0; offset < data.size(); offset += 64) {
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                size_t j = offset + 4 * i;
                w[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | data[j + 3];
            }
            for (int i = 16; i < 64; ++i) {
                uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (int i = 0; i < 64; ++i) {
                uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
                uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;
                hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }
        vector<unsigned char> digest;
        for (uint32_t x : h) {
            digest.push_back((x >> 24) & 0xff);
            digest.push_back((x >> 16) & 0xff);
            digest.push_back((x >> 8) & 0xff);
            digest.push_back(x & 0xff);
        }
        return toHex(digest);
    }
};

static string trim(const string& s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace((unsigned char)s[a])) ++a;
    while (b > a && isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

static string jsonEscape(const string& s) {
    string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

static string jsonUnescape(const string& s) {
    string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char n = s[++i];
            if (n == 'n') out.push_back('\n');
            else if (n == 'r') out.push_back('\r');
            else if (n == 't') out.push_back('\t');
            else out.push_back(n);
        } else out.push_back(s[i]);
    }
    return out;
}

static string readFile(const string& filename) {
    ifstream in(filename);
    if (!in) return "";
    return string((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
}

static vector<string> extractObjects(const string& text) {
    vector<string> objects;
    bool inString = false, esc = false;
    int depth = 0;
    size_t start = string::npos;
    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (inString) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') inString = false;
            continue;
        }
        if (c == '"') inString = true;
        else if (c == '{') {
            if (depth == 0) start = i;
            ++depth;
        } else if (c == '}') {
            --depth;
            if (depth == 0 && start != string::npos) objects.push_back(text.substr(start, i - start + 1));
        }
    }
    return objects;
}

static size_t findKeyColon(const string& obj, const string& key) {
    string pat = "\"" + key + "\"";
    size_t p = obj.find(pat);
    if (p == string::npos) return string::npos;
    p = obj.find(':', p + pat.size());
    return p;
}

static string getJsonString(const string& obj, const string& key, const string& def = "") {
    size_t p = findKeyColon(obj, key);
    if (p == string::npos) return def;
    ++p;
    while (p < obj.size() && isspace((unsigned char)obj[p])) ++p;
    if (p >= obj.size() || obj[p] != '"') return def;
    ++p;
    string raw;
    bool esc = false;
    for (; p < obj.size(); ++p) {
        char c = obj[p];
        if (esc) { raw.push_back('\\'); raw.push_back(c); esc = false; }
        else if (c == '\\') esc = true;
        else if (c == '"') break;
        else raw.push_back(c);
    }
    return jsonUnescape(raw);
}

static long long getJsonLong(const string& obj, const string& key, long long def = 0) {
    size_t p = findKeyColon(obj, key);
    if (p == string::npos) return def;
    ++p;
    while (p < obj.size() && isspace((unsigned char)obj[p])) ++p;
    size_t q = p;
    if (q < obj.size() && obj[q] == '-') ++q;
    while (q < obj.size() && isdigit((unsigned char)obj[q])) ++q;
    if (q == p) return def;
    try { return stoll(obj.substr(p, q - p)); }
    catch (...) { return def; }
}

static bool getJsonBool(const string& obj, const string& key, bool def = false) {
    size_t p = findKeyColon(obj, key);
    if (p == string::npos) return def;
    ++p;
    while (p < obj.size() && isspace((unsigned char)obj[p])) ++p;
    if (obj.compare(p, 4, "true") == 0) return true;
    if (obj.compare(p, 5, "false") == 0) return false;
    return def;
}

static string formatMoney(long long cents) {
    bool neg = cents < 0;
    if (neg) cents = -cents;
    ostringstream out;
    if (neg) out << '-';
    out << cents / 100 << '.' << setw(2) << setfill('0') << (cents % 100);
    return out.str();
}

static bool parseCentsStrict(const string& input, long long& cents, bool allowZero = false) {
    string s = trim(input);
    if (s.empty()) return false;
    size_t i = 0;
    bool neg = false;
    if (s[i] == '+') return false;
    if (s[i] == '-') { neg = true; ++i; }
    if (i >= s.size()) return false;

    string whole, frac;
    bool seenDot = false;
    for (; i < s.size(); ++i) {
        char c = s[i];
        if (c == '.') {
            if (seenDot) return false;
            seenDot = true;
        } else if (isdigit((unsigned char)c)) {
            if (seenDot) frac.push_back(c);
            else whole.push_back(c);
        } else return false;
    }
    if (whole.empty()) whole = "0";
    if (frac.size() > 2) return false;

    try {
        long long w = stoll(whole);
        while (frac.size() < 2) frac.push_back('0');
        long long f = frac.empty() ? 0 : stoll(frac);
        cents = w * 100 + f;
        if (neg) cents = -cents;
    } catch (...) { return false; }

    return allowZero ? cents >= 0 : cents > 0;
}

static string currentTimeString() {
    time_t now = time(nullptr);
    tm localTm{};
#if defined(_WIN32)
    localtime_s(&localTm, &now);
#else
    localtime_r(&now, &localTm);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &localTm);
    return string(buf);
}

static vector<string> splitTokens(const string& line) {
    vector<string> tokens;
    string cur;
    bool inQuote = false;
    for (char c : line) {
        if (c == '"') { inQuote = !inQuote; continue; }
        if (!inQuote && isspace((unsigned char)c)) {
            if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
        } else cur.push_back(c);
    }
    if (!cur.empty()) tokens.push_back(cur);
    return tokens;
}

static string normalizePromptValue(string s) {
    s = trim(s);
    if (s.size() >= 2 && s.front() == '[' && s.back() == ']') {
        string inside = s.substr(1, s.size() - 2);
        size_t colon = inside.find(':');
        if (colon != string::npos) return trim(inside.substr(colon + 1));
        return trim(inside);
    }
    return s;
}

static bool extractInlineField(string& line, const vector<string>& labels, string& value) {
    for (const string& label : labels) {
        string marker = "[" + label + ":";
        size_t p = line.find(marker);
        if (p == string::npos) continue;
        size_t start = p + marker.size();
        size_t end = line.find(']', start);
        if (end == string::npos) end = line.size();
        value = trim(line.substr(start, end - start));
        line.erase(p, (end == line.size() ? end : end + 1) - p);
        line = trim(line);
        return true;
    }
    return false;
}

static bool readField(const string& prompt, const string& inlineValue, bool hasInline, string& value) {
    if (hasInline) {
        value = normalizePromptValue(inlineValue);
        return true;
    }
    cout << prompt << '\n';
    if (!getline(cin, value)) return false;
    value = normalizePromptValue(value);
    return true;
}

static string normalizeAccountNumber(const string& raw) {
    string s = trim(raw);
    string d;
    for (char c : s) {
        if (isdigit((unsigned char)c)) d.push_back(c);
        else if (c != '-') return s;
    }
    if (d.size() != 16) return s;
    return d.substr(0, 4) + "-" + d.substr(4, 4) + "-" + d.substr(8, 4) + "-" + d.substr(12, 4);
}

static bool normalizeNationalCode(const string& raw, string& normalized) {
    string s = trim(raw);
    if (s.size() < 8 || s.size() > 10) return false;
    for (char c : s) if (!isdigit((unsigned char)c)) return false;
    normalized = string(10 - s.size(), '0') + s;
    return true;
}

static bool isValidNationalCode(const string& raw, string& normalized) {
    if (!normalizeNationalCode(raw, normalized)) return false;
    int sum = 0;
    for (int i = 0; i < 9; ++i) sum += (normalized[i] - '0') * (10 - i);
    int rem = sum % 11;
    int control = normalized[9] - '0';
    int expected = (rem < 2) ? rem : (11 - rem);
    return control == expected;
}

struct User {
    string nationalCode;
    string passwordHash;
};

struct Account {
    string number;
    int branchId = 0;
    bool active = true;
    long long balanceCents = 0;
    string passwordHash;
};

struct Transaction {
    int id = 0;
    string time;
    string type;
    string from;
    string to;
    long long amountCents = 0;
    long long feeCents = 0;
    long long fromBalanceAfterCents = 0;
    long long toBalanceAfterCents = 0;
};

struct UserAccountLink {
    string nationalCode;
    string accountNumber;
};

class FeeSettings {
    long long transferFeeCents = 0;
    long long balanceInquiryFeeCents = 0;
    static constexpr const char* FEE_FILE = "fees.json";
public:
    void load() {
        transferFeeCents = 0;
        balanceInquiryFeeCents = 0;
        string text = readFile(FEE_FILE);
        if (text.empty()) return;
        auto objs = extractObjects(text);
        string obj = objs.empty() ? text : objs.front();
        transferFeeCents = getJsonLong(obj, "transfer_fee_cents", 0);
        balanceInquiryFeeCents = getJsonLong(obj, "balance_inquiry_fee_cents", 0);
        if (transferFeeCents < 0) transferFeeCents = 0;
        if (balanceInquiryFeeCents < 0) balanceInquiryFeeCents = 0;
    }
    long long transferFee() const { return transferFeeCents; }
    long long balanceInquiryFee() const { return balanceInquiryFeeCents; }
};

class UserBankSystem {
    vector<User> users;
    vector<Account> accounts;
    vector<Transaction> transactions;
    vector<UserAccountLink> links;
    string currentUser;

    int nextBranchId = 10001;
    int nextTransactionId = 1001;
    long long nextAccountSeq = 1;

    static constexpr const char* USER_FILE = "users.json";
    static constexpr const char* ACCOUNT_FILE = "accounts.json";
    static constexpr const char* TX_FILE = "transactions.json";
    static constexpr const char* META_FILE = "meta.json";
    static constexpr const char* LINK_FILE = "user_accounts.json";

    User* findUser(const string& nationalCode) {
        for (auto& u : users) if (u.nationalCode == nationalCode) return &u;
        return nullptr;
    }
    const User* findUserConst(const string& nationalCode) const {
        for (const auto& u : users) if (u.nationalCode == nationalCode) return &u;
        return nullptr;
    }
    Account* findAccountAny(const string& number) {
        string n = normalizeAccountNumber(number);
        for (auto& a : accounts) if (a.number == n) return &a;
        return nullptr;
    }
    const Account* findAccountAnyConst(const string& number) const {
        string n = normalizeAccountNumber(number);
        for (const auto& a : accounts) if (a.number == n) return &a;
        return nullptr;
    }
    Account* findActiveAccount(const string& number) {
        Account* a = findAccountAny(number);
        return (a && a->active) ? a : nullptr;
    }
    const Account* findActiveAccountConst(const string& number) const {
        const Account* a = findAccountAnyConst(number);
        return (a && a->active) ? a : nullptr;
    }
    bool accountBelongsToCurrentUser(const string& number) const {
        string n = normalizeAccountNumber(number);
        for (const auto& link : links) {
            if (link.nationalCode == currentUser && link.accountNumber == n) return true;
        }
        return false;
    }
    bool userHasAnyActiveAccount(const string& nationalCode) const {
        for (const auto& link : links) {
            if (link.nationalCode != nationalCode) continue;
            const Account* a = findActiveAccountConst(link.accountNumber);
            if (a) return true;
        }
        return false;
    }
    bool checkAccountPassword(const Account& account, const string& password) const {
        return SHA256::hash(password) == account.passwordHash;
    }
    bool checkUserPassword(const User& user, const string& password) const {
        return SHA256::hash(password) == user.passwordHash;
    }
    string makeAccountNumber() {
        ostringstream digits;
        digits << "5022" << setw(12) << setfill('0') << nextAccountSeq++;
        string d = digits.str();
        if (d.size() > 16) d = d.substr(d.size() - 16);
        return d.substr(0,4) + "-" + d.substr(4,4) + "-" + d.substr(8,4) + "-" + d.substr(12,4);
    }
    void saveUsers() const {
        ofstream out(USER_FILE);
        out << "[\n";
        for (size_t i = 0; i < users.size(); ++i) {
            const auto& u = users[i];
            out << "  {\"national_code\":\"" << jsonEscape(u.nationalCode)
                << "\",\"password_hash\":\"" << jsonEscape(u.passwordHash) << "\"}";
            if (i + 1 < users.size()) out << ',';
            out << "\n";
        }
        out << "]\n";
    }
    void saveAccounts() const {
        ofstream out(ACCOUNT_FILE);
        out << "[\n";
        for (size_t i = 0; i < accounts.size(); ++i) {
            const auto& a = accounts[i];
            out << "  {\"number\":\"" << jsonEscape(a.number) << "\",\"branch_id\":" << a.branchId
                << ",\"active\":" << (a.active ? "true" : "false") << ",\"balance_cents\":" << a.balanceCents
                << ",\"password_hash\":\"" << jsonEscape(a.passwordHash) << "\"}";
            if (i + 1 < accounts.size()) out << ',';
            out << "\n";
        }
        out << "]\n";
    }
    void saveTransactions() const {
        ofstream out(TX_FILE);
        out << "[\n";
        for (size_t i = 0; i < transactions.size(); ++i) {
            const auto& t = transactions[i];
            out << "  {\"id\":" << t.id << ",\"time\":\"" << jsonEscape(t.time)
                << "\",\"type\":\"" << jsonEscape(t.type)
                << "\",\"from\":\"" << jsonEscape(t.from)
                << "\",\"to\":\"" << jsonEscape(t.to)
                << "\",\"amount_cents\":" << t.amountCents
                << ",\"fee_cents\":" << t.feeCents
                << ",\"from_balance_after_cents\":" << t.fromBalanceAfterCents
                << ",\"to_balance_after_cents\":" << t.toBalanceAfterCents << "}";
            if (i + 1 < transactions.size()) out << ',';
            out << "\n";
        }
        out << "]\n";
    }
    void saveLinks() const {
        ofstream out(LINK_FILE);
        out << "[\n";
        for (size_t i = 0; i < links.size(); ++i) {
            const auto& l = links[i];
            out << "  {\"national_code\":\"" << jsonEscape(l.nationalCode)
                << "\",\"account_number\":\"" << jsonEscape(l.accountNumber) << "\"}";
            if (i + 1 < links.size()) out << ',';
            out << "\n";
        }
        out << "]\n";
    }
    void saveMeta() const {
        ofstream out(META_FILE);
        out << "{\n";
        out << "  \"next_branch_id\": " << nextBranchId << ",\n";
        out << "  \"next_transaction_id\": " << nextTransactionId << ",\n";
        out << "  \"next_account_seq\": " << nextAccountSeq << "\n";
        out << "}\n";
    }
    void saveAll() const {
        saveUsers();
        saveAccounts();
        saveTransactions();
        saveLinks();
        saveMeta();
    }
    void recomputeNextIdsIfNeeded() {
        int maxTx = 1000;
        long long maxSeq = 0;
        for (const auto& t : transactions) maxTx = max(maxTx, t.id);
        for (const auto& a : accounts) {
            string d;
            for (char c : a.number) if (isdigit((unsigned char)c)) d.push_back(c);
            if (d.rfind("5022", 0) == 0 && d.size() == 16) {
                try { maxSeq = max(maxSeq, stoll(d.substr(4))); } catch (...) {}
            }
        }
        nextTransactionId = max(nextTransactionId, maxTx + 1);
        nextAccountSeq = max(nextAccountSeq, maxSeq + 1);
    }
    void removeLinksForMissingAccounts() {
        links.erase(remove_if(links.begin(), links.end(), [&](const UserAccountLink& l) {
            return findActiveAccountConst(l.accountNumber) == nullptr;
        }), links.end());
    }
public:
    void load() {
        users.clear();
        accounts.clear();
        transactions.clear();
        links.clear();

        for (const string& obj : extractObjects(readFile(USER_FILE))) {
            User u;
            u.nationalCode = getJsonString(obj, "national_code");
            u.passwordHash = getJsonString(obj, "password_hash");
            if (!u.nationalCode.empty()) users.push_back(u);
        }
        for (const string& obj : extractObjects(readFile(ACCOUNT_FILE))) {
            Account a;
            a.number = normalizeAccountNumber(getJsonString(obj, "number"));
            a.branchId = (int)getJsonLong(obj, "branch_id", 0);
            a.active = getJsonBool(obj, "active", true);
            a.balanceCents = getJsonLong(obj, "balance_cents", 0);
            a.passwordHash = getJsonString(obj, "password_hash");
            if (!a.number.empty()) accounts.push_back(a);
        }
        for (const string& obj : extractObjects(readFile(TX_FILE))) {
            Transaction t;
            t.id = (int)getJsonLong(obj, "id");
            t.time = getJsonString(obj, "time");
            t.type = getJsonString(obj, "type");
            t.from = normalizeAccountNumber(getJsonString(obj, "from"));
            t.to = normalizeAccountNumber(getJsonString(obj, "to"));
            t.amountCents = getJsonLong(obj, "amount_cents", 0);
            t.feeCents = getJsonLong(obj, "fee_cents", 0);
            t.fromBalanceAfterCents = getJsonLong(obj, "from_balance_after_cents", 0);
            t.toBalanceAfterCents = getJsonLong(obj, "to_balance_after_cents", 0);
            if (t.id) transactions.push_back(t);
        }
        for (const string& obj : extractObjects(readFile(LINK_FILE))) {
            UserAccountLink l;
            l.nationalCode = getJsonString(obj, "national_code");
            l.accountNumber = normalizeAccountNumber(getJsonString(obj, "account_number"));
            if (!l.nationalCode.empty() && !l.accountNumber.empty()) links.push_back(l);
        }

        string meta = readFile(META_FILE);
        if (!meta.empty()) {
            auto objs = extractObjects(meta);
            string obj = objs.empty() ? meta : objs.front();
            nextBranchId = (int)getJsonLong(obj, "next_branch_id", nextBranchId);
            nextTransactionId = (int)getJsonLong(obj, "next_transaction_id", nextTransactionId);
            nextAccountSeq = getJsonLong(obj, "next_account_seq", nextAccountSeq);
        }
        recomputeNextIdsIfNeeded();
        removeLinksForMissingAccounts();
    }

    void signup(const string& nationalCodeInput, const string& password) {
        if (!currentUser.empty()) { cout << "Error: User already logged in.\n"; return; }
        string code;
        if (!isValidNationalCode(nationalCodeInput, code)) { cout << "Error: Invalid national code.\n"; return; }
        if (findUserConst(code)) { cout << "Error: User already exists.\n"; return; }
        users.push_back({code, SHA256::hash(password)});
        saveAll();
        cout << "User created.\n";
    }

    void login(const string& nationalCodeInput, const string& password) {
        if (!currentUser.empty()) { cout << "Error: User already logged in.\n"; return; }
        string code;
        if (!normalizeNationalCode(nationalCodeInput, code)) code = trim(nationalCodeInput);
        User* u = findUser(code);
        if (!u) { cout << "Error: User not found.\n"; return; }
        if (!checkUserPassword(*u, password)) { cout << "Error: Wrong user password.\n"; return; }
        currentUser = code;
        cout << "Logged in.\n";
    }

    void logout() {
        if (currentUser.empty()) { cout << "Error: No user logged in.\n"; return; }
        currentUser.clear();
        cout << "Logged out.\n";
    }

    void openAccount(const string& accountPassword) {
        if (currentUser.empty()) { cout << "Error: No user logged in.\n"; return; }
        Account a;
        a.number = makeAccountNumber();
        a.branchId = 0;
        a.active = true;
        a.balanceCents = 0;
        a.passwordHash = SHA256::hash(accountPassword);
        accounts.push_back(a);
        links.push_back({currentUser, a.number});
        saveAll();
        cout << "Account created. Number: " << a.number << '\n';
    }

    void myAccounts() const {
        if (currentUser.empty()) { cout << "Error: No user logged in.\n"; return; }
        for (const auto& link : links) {
            if (link.nationalCode != currentUser) continue;
            const Account* a = findActiveAccountConst(link.accountNumber);
            if (a) cout << a->number << " | Balance: " << formatMoney(a->balanceCents) << '\n';
        }
    }

    void deleteMyAccount(const string& accountNumber, const string& accountPassword) {
        if (currentUser.empty()) { cout << "Error: No user logged in.\n"; return; }
        string n = normalizeAccountNumber(accountNumber);
        Account* a = findActiveAccount(n);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        if (!accountBelongsToCurrentUser(n)) { cout << "Error: Account does not belong to user.\n"; return; }
        if (!checkAccountPassword(*a, accountPassword)) { cout << "Error: Wrong account password.\n"; return; }
        if (a->balanceCents > 0) { cout << "Error: Account balance is positive.\n"; return; }

        accounts.erase(remove_if(accounts.begin(), accounts.end(), [&](const Account& x) { return x.number == n; }), accounts.end());
        links.erase(remove_if(links.begin(), links.end(), [&](const UserAccountLink& l) { return l.accountNumber == n; }), links.end());
        transactions.erase(remove_if(transactions.begin(), transactions.end(), [&](const Transaction& t) { return t.from == n || t.to == n; }), transactions.end());
        saveAll();
        cout << "Account deleted.\n";
    }

    void depositTo(const string& accountNumber, long long amountCents) {
        string n = normalizeAccountNumber(accountNumber);
        Account* a = findActiveAccount(n);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        if (amountCents <= 0) { cout << "Error: Amount must be positive.\n"; return; }

        a->balanceCents += amountCents;
        Transaction t;
        t.id = nextTransactionId++;
        t.time = currentTimeString();
        t.type = "DEPOSIT";
        t.from = "";
        t.to = n;
        t.amountCents = amountCents;
        t.toBalanceAfterCents = a->balanceCents;
        transactions.push_back(t);
        saveAll();
        cout << "Transaction ID: " << t.id << '\n';
        cout << "New balance: " << formatMoney(a->balanceCents) << '\n';
    }

    void withdrawFrom(const string& accountNumber, long long amountCents, const string& accountPassword) {
        if (currentUser.empty()) { cout << "Error: No user logged in.\n"; return; }
        string n = normalizeAccountNumber(accountNumber);
        Account* a = findActiveAccount(n);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        if (!accountBelongsToCurrentUser(n)) { cout << "Error: Account does not belong to user.\n"; return; }
        if (amountCents <= 0) { cout << "Error: Amount must be positive.\n"; return; }
        if (!checkAccountPassword(*a, accountPassword)) { cout << "Error: Wrong account password.\n"; return; }
        if (a->balanceCents < amountCents) { cout << "Error: Insufficient funds.\n"; return; }

        a->balanceCents -= amountCents;
        Transaction t;
        t.id = nextTransactionId++;
        t.time = currentTimeString();
        t.type = "WITHDRAWAL";
        t.from = n;
        t.to = "";
        t.amountCents = amountCents;
        t.fromBalanceAfterCents = a->balanceCents;
        transactions.push_back(t);
        saveAll();
        cout << "Transaction ID: " << t.id << '\n';
        cout << "New balance: " << formatMoney(a->balanceCents) << '\n';
    }

    void sendMoney(const string& fromAccount, const string& toAccount, long long amountCents, const string& accountPassword) {
        if (currentUser.empty()) { cout << "Error: No user logged in.\n"; return; }
        string from = normalizeAccountNumber(fromAccount);
        string to = normalizeAccountNumber(toAccount);
        Account* src = findActiveAccount(from);
        if (!src) { cout << "Error: Source account not found.\n"; return; }
        Account* dst = findActiveAccount(to);
        if (!dst) { cout << "Error: Destination account not found.\n"; return; }
        if (!accountBelongsToCurrentUser(from)) { cout << "Error: Account does not belong to user.\n"; return; }
        if (amountCents <= 0) { cout << "Error: Amount must be positive.\n"; return; }
        if (!checkAccountPassword(*src, accountPassword)) { cout << "Error: Wrong account password.\n"; return; }

        FeeSettings fees;
        fees.load();
        long long fee = fees.transferFee();
        if (src->balanceCents < amountCents + fee) { cout << "Error: Insufficient funds.\n"; return; }

        src->balanceCents -= amountCents + fee;
        dst->balanceCents += amountCents;
        Transaction t;
        t.id = nextTransactionId++;
        t.time = currentTimeString();
        t.type = "TRANSFER";
        t.from = from;
        t.to = to;
        t.amountCents = amountCents;
        t.feeCents = fee;
        t.fromBalanceAfterCents = src->balanceCents;
        t.toBalanceAfterCents = dst->balanceCents;
        transactions.push_back(t);
        saveAll();
        cout << "Transaction ID: " << t.id << '\n';
        cout << "Transfer fee: " << formatMoney(fee) << '\n';
        cout << "New balance: " << formatMoney(src->balanceCents) << '\n';
    }

    void balanceInquiry(const string& accountNumber) {
        if (currentUser.empty()) { cout << "Error: No user logged in.\n"; return; }
        string n = normalizeAccountNumber(accountNumber);
        Account* a = findActiveAccount(n);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        if (!accountBelongsToCurrentUser(n)) { cout << "Error: Account does not belong to user.\n"; return; }

        FeeSettings fees;
        fees.load();
        long long fee = fees.balanceInquiryFee();
        if (a->balanceCents < fee) { cout << "Error: Insufficient funds.\n"; return; }

        a->balanceCents -= fee;
        Transaction t;
        t.id = nextTransactionId++;
        t.time = currentTimeString();
        t.type = "BALANCE_INQUIRY_FEE";
        t.from = n;
        t.to = "";
        t.amountCents = 0;
        t.feeCents = fee;
        t.fromBalanceAfterCents = a->balanceCents;
        transactions.push_back(t);
        saveAll();
        cout << "Balance inquiry fee: " << formatMoney(fee) << '\n';
        cout << "Balance: " << formatMoney(a->balanceCents) << '\n';
    }

    void deleteMyUser(const string& userPassword) {
        if (currentUser.empty()) { cout << "Error: No user logged in.\n"; return; }
        User* u = findUser(currentUser);
        if (!u) { currentUser.clear(); cout << "Error: User not found.\n"; return; }
        if (!checkUserPassword(*u, userPassword)) { cout << "Error: Wrong user password.\n"; return; }
        if (userHasAnyActiveAccount(currentUser)) { cout << "Error: User has accounts.\n"; return; }

        string deletedCode = currentUser;
        users.erase(remove_if(users.begin(), users.end(), [&](const User& x) { return x.nationalCode == deletedCode; }), users.end());
        links.erase(remove_if(links.begin(), links.end(), [&](const UserAccountLink& l) { return l.nationalCode == deletedCode; }), links.end());
        currentUser.clear();
        saveAll();
        cout << "User deleted.\n";
    }
};

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    cout << unitbuf;

    UserBankSystem bank;
    bank.load();

    string originalLine;
    while (getline(cin, originalLine)) {
        string line = trim(originalLine);
        if (line.empty()) continue;

        string inlineAccountPassword, inlineUserPassword, inlineNationalCode;
        bool hasInlineAccountPassword = extractInlineField(line, {"account password", "password"}, inlineAccountPassword);
        bool hasInlineUserPassword = extractInlineField(line, {"user password", "password"}, inlineUserPassword);
        bool hasInlineNationalCode = extractInlineField(line, {"national code"}, inlineNationalCode);

        vector<string> tokens = splitTokens(line);
        if (tokens.empty()) continue;
        string cmd = tokens[0];

        try {
            if (cmd == "signup") {
                string code, pass;
                if (!readField("Enter national code:", inlineNationalCode, hasInlineNationalCode, code)) break;
                if (!readField("Enter user password:", inlineUserPassword, hasInlineUserPassword, pass)) break;
                bank.signup(code, pass);
            } else if (cmd == "login") {
                string code, pass;
                if (!readField("Enter national code:", inlineNationalCode, hasInlineNationalCode, code)) break;
                if (!readField("Enter user password:", inlineUserPassword, hasInlineUserPassword, pass)) break;
                bank.login(code, pass);
            } else if (cmd == "logout") {
                bank.logout();
            } else if (cmd == "open_account") {
                string pass;
                if (!readField("Enter account password:", inlineAccountPassword, hasInlineAccountPassword, pass)) break;
                bank.openAccount(pass);
            } else if (cmd == "my_accounts") {
                bank.myAccounts();
            } else if (cmd == "delete_my_account") {
                if (tokens.size() != 2) { cout << "Error: Invalid command.\n"; continue; }
                string pass;
                if (!readField("Enter account password:", inlineAccountPassword, hasInlineAccountPassword, pass)) break;
                bank.deleteMyAccount(tokens[1], pass);
            } else if (cmd == "deposit_to") {
                if (tokens.size() != 3) { cout << "Error: Invalid command.\n"; continue; }
                long long amount;
                if (!parseCentsStrict(tokens[2], amount, false)) { cout << "Error: Amount must be positive.\n"; continue; }
                bank.depositTo(tokens[1], amount);
            } else if (cmd == "withdraw_from") {
                if (tokens.size() != 3) { cout << "Error: Invalid command.\n"; continue; }
                long long amount;
                if (!parseCentsStrict(tokens[2], amount, false)) { cout << "Error: Amount must be positive.\n"; continue; }
                string pass;
                if (!readField("Enter account password:", inlineAccountPassword, hasInlineAccountPassword, pass)) break;
                bank.withdrawFrom(tokens[1], amount, pass);
            } else if (cmd == "send_money") {
                if (tokens.size() != 4) { cout << "Error: Invalid command.\n"; continue; }
                long long amount;
                if (!parseCentsStrict(tokens[3], amount, false)) { cout << "Error: Amount must be positive.\n"; continue; }
                string pass;
                if (!readField("Enter account password:", inlineAccountPassword, hasInlineAccountPassword, pass)) break;
                bank.sendMoney(tokens[1], tokens[2], amount, pass);
            } else if (cmd == "balance_inquiry") {
                if (tokens.size() != 2) { cout << "Error: Invalid command.\n"; continue; }
                bank.balanceInquiry(tokens[1]);
            } else if (cmd == "delete_my_user") {
                string pass;
                if (!readField("Enter user password:", inlineUserPassword, hasInlineUserPassword, pass)) break;
                bank.deleteMyUser(pass);
            } else if (cmd == "exit" || cmd == "quit") {
                break;
            } else {
                cout << "Error: Invalid command.\n";
            }
        } catch (...) {
            cout << "Error: Invalid command.\n";
        }
    }
    return 0;
}
