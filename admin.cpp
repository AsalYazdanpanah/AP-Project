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

static long long parseCents(string s) {
    s = trim(s);
    bool neg = false;
    if (!s.empty() && s[0] == '-') { neg = true; s.erase(s.begin()); }
    string whole = s, frac = "";
    size_t dot = s.find('.');
    if (dot != string::npos) {
        whole = s.substr(0, dot);
        frac = s.substr(dot + 1);
    }
    long long w = whole.empty() ? 0 : stoll(whole);
    while (frac.size() < 2) frac.push_back('0');
    if (frac.size() > 2) frac = frac.substr(0, 2);
    long long f = frac.empty() ? 0 : stoll(frac);
    long long ans = w * 100 + f;
    return neg ? -ans : ans;
}


static bool parseCentsStrict(const string& input, long long& cents, bool allowZero) {
    string s = trim(input);
    if (s.empty()) return false;
    size_t i = 0;
    if (s[i] == '+') return false;
    bool neg = false;
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
    if (allowZero) return cents >= 0;
    return cents > 0;
}

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
    void save() const {
        ofstream out(FEE_FILE);
        out << "{\n";
        out << "  \"transfer_fee_cents\": " << transferFeeCents << ",\n";
        out << "  \"balance_inquiry_fee_cents\": " << balanceInquiryFeeCents << "\n";
        out << "}\n";
    }
    void setTransferFee(long long cents) {
        load();
        transferFeeCents = cents;
        save();
        cout << "Transfer fee set to " << formatMoney(transferFeeCents) << '\n';
    }
    void setBalanceInquiryFee(long long cents) {
        load();
        balanceInquiryFeeCents = cents;
        save();
        cout << "Balance inquiry fee set to " << formatMoney(balanceInquiryFeeCents) << '\n';
    }
    void show() {
        load();
        cout << "Transfer fee: " << formatMoney(transferFeeCents) << '\n';
        cout << "Balance inquiry fee: " << formatMoney(balanceInquiryFeeCents) << '\n';
    }
};

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

struct Branch { int id; string name; };
struct Account { string number; int branchId; bool active; long long balanceCents; string passwordHash; };
struct Transaction {
    int id;
    string time;
    string type;
    string from;
    string to;
    long long amountCents;
    long long fromBalanceAfterCents;
    long long toBalanceAfterCents;
};

class BankSystem {
    vector<Branch> branches;
    vector<Account> accounts;
    vector<Transaction> transactions;
    int nextBranchId = 10001;
    int nextTransactionId = 1001;
    long long nextAccountSeq = 1;

    static constexpr const char* BRANCH_FILE = "branches.json";
    static constexpr const char* ACCOUNT_FILE = "accounts.json";
    static constexpr const char* TX_FILE = "transactions.json";
    static constexpr const char* META_FILE = "meta.json";

    Account* findAccount(const string& number) {
        for (auto& a : accounts) if (a.number == number) return &a;
        return nullptr;
    }
    const Account* findAccountConst(const string& number) const {
        for (const auto& a : accounts) if (a.number == number) return &a;
        return nullptr;
    }
    bool branchExists(int id) const {
        for (const auto& b : branches) if (b.id == id) return true;
        return false;
    }
    string makeAccountNumber() {
        ostringstream digits;
        digits << "5022" << setw(12) << setfill('0') << nextAccountSeq++;
        string d = digits.str();
        return d.substr(0,4) + "-" + d.substr(4,4) + "-" + d.substr(8,4) + "-" + d.substr(12,4);
    }
    bool checkPassword(const Account& acc, const string& password) const {
        return SHA256::hash(password) == acc.passwordHash;
    }
    void saveBranches() const {
        ofstream out(BRANCH_FILE);
        out << "[\n";
        for (size_t i = 0; i < branches.size(); ++i) {
            const auto& b = branches[i];
            out << "  {\"id\":" << b.id << ",\"name\":\"" << jsonEscape(b.name) << "\"}";
            if (i + 1 < branches.size()) out << ',';
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
                << ",\"password_hash\":\"" << a.passwordHash << "\"}";
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
            out << "  {\"id\":" << t.id << ",\"time\":\"" << jsonEscape(t.time) << "\",\"type\":\"" << t.type
                << "\",\"from\":\"" << jsonEscape(t.from) << "\",\"to\":\"" << jsonEscape(t.to)
                << "\",\"amount_cents\":" << t.amountCents
                << ",\"from_balance_after_cents\":" << t.fromBalanceAfterCents
                << ",\"to_balance_after_cents\":" << t.toBalanceAfterCents << "}";
            if (i + 1 < transactions.size()) out << ',';
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
        saveBranches();
        saveAccounts();
        saveTransactions();
        saveMeta();
    }
    void recomputeNextIdsIfNeeded() {
        int maxBranch = 10000;
        int maxTx = 1000;
        long long maxSeq = 0;
        for (const auto& b : branches) maxBranch = max(maxBranch, b.id);
        for (const auto& t : transactions) maxTx = max(maxTx, t.id);
        for (const auto& a : accounts) {
            string d;
            for (char c : a.number) if (isdigit((unsigned char)c)) d.push_back(c);
            if (d.rfind("5022", 0) == 0 && d.size() == 16) {
                try { maxSeq = max(maxSeq, stoll(d.substr(4))); } catch (...) {}
            }
        }
        nextBranchId = max(nextBranchId, maxBranch + 1);
        nextTransactionId = max(nextTransactionId, maxTx + 1);
        nextAccountSeq = max(nextAccountSeq, maxSeq + 1);
    }
public:
    void load() {
        branches.clear(); accounts.clear(); transactions.clear();
        for (const string& obj : extractObjects(readFile(BRANCH_FILE))) {
            branches.push_back({(int)getJsonLong(obj, "id"), getJsonString(obj, "name")});
        }
        for (const string& obj : extractObjects(readFile(ACCOUNT_FILE))) {
            Account a;
            a.number = getJsonString(obj, "number");
            a.branchId = (int)getJsonLong(obj, "branch_id");
            a.active = getJsonBool(obj, "active", true);
            a.balanceCents = getJsonLong(obj, "balance_cents");
            a.passwordHash = getJsonString(obj, "password_hash");
            if (!a.number.empty()) accounts.push_back(a);
        }
        for (const string& obj : extractObjects(readFile(TX_FILE))) {
            Transaction t;
            t.id = (int)getJsonLong(obj, "id");
            t.time = getJsonString(obj, "time");
            t.type = getJsonString(obj, "type");
            t.from = getJsonString(obj, "from");
            t.to = getJsonString(obj, "to");
            t.amountCents = getJsonLong(obj, "amount_cents");
            t.fromBalanceAfterCents = getJsonLong(obj, "from_balance_after_cents");
            t.toBalanceAfterCents = getJsonLong(obj, "to_balance_after_cents");
            if (t.id) transactions.push_back(t);
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
    }

    bool hasBranch(int id) const {
        return branchExists(id);
    }
    bool hasAccount(const string& number) const {
        return findAccountConst(number) != nullptr;
    }
    bool accountIsActive(const string& number) const {
        const Account* a = findAccountConst(number);
        return a && a->active;
    }

    void createBranch(const string& name) {
        Branch b{nextBranchId++, name};
        branches.push_back(b);
        saveAll();
        cout << "Branch created. ID: " << b.id << '\n';
    }
    void listBranches() const {
        for (const auto& b : branches) cout << b.id << " | " << b.name << '\n';
    }
    void createAccount(int branchId, const string& password) {
        if (!branchExists(branchId)) {
            cout << "Error: Branch not found.\n";
            return;
        }
        Account a;
        a.number = makeAccountNumber();
        a.branchId = branchId;
        a.active = true;
        a.balanceCents = 0;
        a.passwordHash = SHA256::hash(password);
        accounts.push_back(a);
        saveAll();
        cout << "Account created. Number: " << a.number << '\n';
    }
    void closeAccount(const string& number, const string& password) {
        Account* a = findAccount(number);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        if (!checkPassword(*a, password)) { cout << "Error: Wrong password.\n"; return; }
        a->active = false;
        saveAll();
        cout << "Account closed.\n";
    }
    void deleteAccount(const string& number, const string& password) {
        Account* a = findAccount(number);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        if (!checkPassword(*a, password)) { cout << "Error: Wrong password.\n"; return; }
        accounts.erase(remove_if(accounts.begin(), accounts.end(), [&](const Account& x){ return x.number == number; }), accounts.end());
        transactions.erase(remove_if(transactions.begin(), transactions.end(), [&](const Transaction& t){ return t.from == number || t.to == number; }), transactions.end());
        saveAll();
        cout << "Account deleted.\n";
    }
    void listAccounts() const {
        for (const auto& a : accounts) {
            cout << a.number << " | Branch: " << a.branchId << " | Active: " << (a.active ? "Yes" : "No")
                 << " | Balance: " << formatMoney(a.balanceCents) << '\n';
        }
    }
    void deposit(const string& number, long long amount) {
        Account* a = findAccount(number);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        if (!a->active) { cout << "Error: Account is inactive.\n"; return; }
        a->balanceCents += amount;
        Transaction t;
        t.id = nextTransactionId++;
        t.time = currentTimeString();
        t.type = "DEPOSIT";
        t.from = "";
        t.to = number;
        t.amountCents = amount;
        t.fromBalanceAfterCents = 0;
        t.toBalanceAfterCents = a->balanceCents;
        transactions.push_back(t);
        saveAll();
        cout << "Transaction ID: " << t.id << '\n';
        cout << "New balance: " << formatMoney(a->balanceCents) << '\n';
    }
    void withdraw(const string& number, long long amount, const string& password) {
        Account* a = findAccount(number);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        if (!a->active) { cout << "Error: Account is inactive.\n"; return; }
        if (!checkPassword(*a, password)) { cout << "Error: Wrong password.\n"; return; }
        if (a->balanceCents < amount) { cout << "Error: Insufficient funds.\n"; return; }
        a->balanceCents -= amount;
        Transaction t;
        t.id = nextTransactionId++;
        t.time = currentTimeString();
        t.type = "WITHDRAWAL";
        t.from = number;
        t.to = "";
        t.amountCents = amount;
        t.fromBalanceAfterCents = a->balanceCents;
        t.toBalanceAfterCents = 0;
        transactions.push_back(t);
        saveAll();
        cout << "Transaction ID: " << t.id << '\n';
        cout << "New balance: " << formatMoney(a->balanceCents) << '\n';
    }
    void transfer(const string& from, const string& to, long long amount, const string& password) {
        Account* src = findAccount(from);
        Account* dst = findAccount(to);
        if (!src) { cout << "Error: Source account not found.\n"; return; }
        if (!dst) { cout << "Error: Destination account not found.\n"; return; }
        if (!src->active || !dst->active) { cout << "Error: Account is inactive.\n"; return; }
        if (!checkPassword(*src, password)) { cout << "Error: Wrong password.\n"; return; }
        if (src->balanceCents < amount) { cout << "Error: Insufficient funds.\n"; return; }
        src->balanceCents -= amount;
        dst->balanceCents += amount;
        Transaction t;
        t.id = nextTransactionId++;
        t.time = currentTimeString();
        t.type = "TRANSFER";
        t.from = from;
        t.to = to;
        t.amountCents = amount;
        t.fromBalanceAfterCents = src->balanceCents;
        t.toBalanceAfterCents = dst->balanceCents;
        transactions.push_back(t);
        saveAll();
        cout << "Transaction ID: " << t.id << '\n';
        cout << "New balance: " << formatMoney(src->balanceCents) << '\n';
    }
    void getBalance(const string& number) const {
        const Account* a = findAccountConst(number);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        cout << "Balance: " << formatMoney(a->balanceCents) << '\n';
        cout << "Active: " << (a->active ? "Yes" : "No") << '\n';
        cout << "Branch: " << a->branchId << '\n';
    }
    void getHistory(const string& number) const {
        if (!findAccountConst(number)) { cout << "Error: Account not found.\n"; return; }
        for (const auto& t : transactions) {
            if (t.to == number && t.type == "DEPOSIT") {
                cout << t.id << " | " << t.time << " | DEPOSIT | +" << formatMoney(t.amountCents)
                     << " | Balance: " << formatMoney(t.toBalanceAfterCents) << '\n';
            } else if (t.from == number && t.type == "WITHDRAWAL") {
                cout << t.id << " | " << t.time << " | WITHDRAWAL | -" << formatMoney(t.amountCents)
                     << " | Balance: " << formatMoney(t.fromBalanceAfterCents) << '\n';
            } else if (t.from == number && t.type == "TRANSFER") {
                cout << t.id << " | " << t.time << " | TRANSFER | -" << formatMoney(t.amountCents)
                     << " | Balance: " << formatMoney(t.fromBalanceAfterCents) << '\n';
            } else if (t.to == number && t.type == "TRANSFER") {
                cout << t.id << " | " << t.time << " | TRANSFER | +" << formatMoney(t.amountCents)
                     << " | Balance: " << formatMoney(t.toBalanceAfterCents) << '\n';
            }
        }
    }
    void getTransaction(int id) const {
        for (const auto& t : transactions) {
            if (t.id == id) {
                cout << "ID: " << t.id << '\n';
                cout << "Time: " << t.time << '\n';
                cout << "Type: " << t.type << '\n';
                cout << "From: " << t.from << '\n';
                cout << "To: " << t.to << '\n';
                cout << "Amount: " << formatMoney(t.amountCents) << '\n';
                long long bal = (t.type == "DEPOSIT") ? t.toBalanceAfterCents : t.fromBalanceAfterCents;
                cout << "Balance after: " << formatMoney(bal) << '\n';
                return;
            }
        }
        cout << "Error: Transaction not found.\n";
    }
    void clearHistory(const string& number, const string& password) {
        Account* a = findAccount(number);
        if (!a) { cout << "Error: Account not found.\n"; return; }
        if (!checkPassword(*a, password)) { cout << "Error: Wrong password.\n"; return; }
        transactions.erase(remove_if(transactions.begin(), transactions.end(), [&](const Transaction& t){ return t.from == number || t.to == number; }), transactions.end());
        saveAll();
        cout << "History cleared for " << number << ".\n";
    }
    void resetAll() {
        branches.clear(); accounts.clear(); transactions.clear();
        nextBranchId = 10001;
        nextTransactionId = 1001;
        nextAccountSeq = 1;
        saveAll();
        cout << "All data cleared.\n";
    }
};

static vector<string> splitTokens(const string& line) {
    vector<string> tokens;
    string cur;
    bool inQuote = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') { inQuote = !inQuote; continue; }
        if (!inQuote && isspace((unsigned char)c)) {
            if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
        } else cur.push_back(c);
    }
    if (!cur.empty()) tokens.push_back(cur);
    return tokens;
}

static string extractBranchName(const string& line) {
    size_t q1 = line.find('"');
    if (q1 != string::npos) {
        size_t q2 = line.find_last_of('"');
        if (q2 != string::npos && q2 > q1) return line.substr(q1 + 1, q2 - q1 - 1);
    }
    string prefix = "create_branch";
    if (line.rfind(prefix, 0) == 0) return trim(line.substr(prefix.size()));
    return "";
}

static bool extractInlinePassword(string& line, string& password) {
    string marker = "[password:";
    size_t p = line.find(marker);
    if (p == string::npos) return false;
    size_t start = p + marker.size();
    size_t end = line.find(']', start);
    if (end == string::npos) end = line.size();
    password = trim(line.substr(start, end - start));
    line.erase(p, (end == line.size() ? end : end + 1) - p);
    line = trim(line);
    return true;
}

static bool getPasswordFromInput(const string& inlinePassword, bool hasInline, string& password) {
    if (hasInline) { password = inlinePassword; return true; }
    cout << "Enter password:\n";
    if (!getline(cin, password)) return false;
    return true;
}

static bool getConfirmationFromInput(string& answer) {
    cout << "Are you sure? This deletes everything. (yes/no): ";
    if (!getline(cin, answer)) return false;
    answer = trim(answer);
    return true;
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    cout << unitbuf;

    BankSystem bank;
    bank.load();

    string originalLine;
    while (getline(cin, originalLine)) {
        string line = trim(originalLine);
        if (line.empty()) continue;
        string inlinePass;
        bool hasInlinePass = extractInlinePassword(line, inlinePass);
        vector<string> tokens = splitTokens(line);
        if (tokens.empty()) continue;
        string cmd = tokens[0];

        try {
            if (cmd == "create_branch") {
                bank.createBranch(extractBranchName(line));
            } else if (cmd == "list_branches") {
                bank.listBranches();
            } else if (cmd == "create_account") {
                if (tokens.size() < 2) continue;
                int branchId = stoi(tokens[1]);
                if (!bank.hasBranch(branchId)) { cout << "Error: Branch not found.\n"; continue; }
                string pass;
                if (!getPasswordFromInput(inlinePass, hasInlinePass, pass)) {
                    cout << "Error: Password timeout. Transaction cancelled.\n";
                    continue;
                }
                bank.createAccount(branchId, pass);
            } else if (cmd == "close_account") {
                if (tokens.size() < 2) continue;
                if (!bank.hasAccount(tokens[1])) { cout << "Error: Account not found.\n"; continue; }
                string pass;
                if (!getPasswordFromInput(inlinePass, hasInlinePass, pass)) { cout << "Error: Password timeout. Transaction cancelled.\n"; continue; }
                bank.closeAccount(tokens[1], pass);
            } else if (cmd == "delete_account") {
                if (tokens.size() < 2) continue;
                if (!bank.hasAccount(tokens[1])) { cout << "Error: Account not found.\n"; continue; }
                string pass;
                if (!getPasswordFromInput(inlinePass, hasInlinePass, pass)) { cout << "Error: Password timeout. Transaction cancelled.\n"; continue; }
                bank.deleteAccount(tokens[1], pass);
            } else if (cmd == "list_accounts") {
                bank.listAccounts();
            } else if (cmd == "deposit") {
                if (tokens.size() < 3) continue;
                bank.deposit(tokens[1], parseCents(tokens[2]));
            } else if (cmd == "withdraw") {
                if (tokens.size() < 3) continue;
                if (!bank.hasAccount(tokens[1])) { cout << "Error: Account not found.\n"; continue; }
                if (!bank.accountIsActive(tokens[1])) { cout << "Error: Account is inactive.\n"; continue; }
                string pass;
                if (!getPasswordFromInput(inlinePass, hasInlinePass, pass)) { cout << "Error: Password timeout. Transaction cancelled.\n"; continue; }
                bank.withdraw(tokens[1], parseCents(tokens[2]), pass);
            } else if (cmd == "transfer") {
                if (tokens.size() < 4) continue;
                if (!bank.hasAccount(tokens[1])) { cout << "Error: Source account not found.\n"; continue; }
                if (!bank.hasAccount(tokens[2])) { cout << "Error: Destination account not found.\n"; continue; }
                if (!bank.accountIsActive(tokens[1]) || !bank.accountIsActive(tokens[2])) { cout << "Error: Account is inactive.\n"; continue; }
                string pass;
                if (!getPasswordFromInput(inlinePass, hasInlinePass, pass)) { cout << "Error: Password timeout. Transaction cancelled.\n"; continue; }
                bank.transfer(tokens[1], tokens[2], parseCents(tokens[3]), pass);
            } else if (cmd == "get_balance") {
                if (tokens.size() < 2) continue;
                bank.getBalance(tokens[1]);
            } else if (cmd == "get_history") {
                if (tokens.size() < 2) continue;
                bank.getHistory(tokens[1]);
            } else if (cmd == "get_transaction") {
                if (tokens.size() < 2) continue;
                bank.getTransaction(stoi(tokens[1]));
            } else if (cmd == "clear_history") {
                if (tokens.size() < 2) continue;
                if (!bank.hasAccount(tokens[1])) { cout << "Error: Account not found.\n"; continue; }
                string pass;
                if (!getPasswordFromInput(inlinePass, hasInlinePass, pass)) { cout << "Error: Password timeout. Transaction cancelled.\n"; continue; }
                bank.clearHistory(tokens[1], pass);
            } else if (cmd == "reset_all") {
                string answer;
                if (!getConfirmationFromInput(answer)) continue;
                if (answer == "yes") bank.resetAll();
                else cout << "Cancelled.\n";
            } else if (cmd == "set_transfer_fee") {
                long long cents;
                if (tokens.size() != 2 || !parseCentsStrict(tokens[1], cents, true)) {
                    cout << "Error: Invalid fee amount.\n";
                    continue;
                }
                FeeSettings fees;
                fees.setTransferFee(cents);
            } else if (cmd == "set_balance_inquiry_fee") {
                long long cents;
                if (tokens.size() != 2 || !parseCentsStrict(tokens[1], cents, true)) {
                    cout << "Error: Invalid fee amount.\n";
                    continue;
                }
                FeeSettings fees;
                fees.setBalanceInquiryFee(cents);
            } else if (cmd == "show_fees") {
                FeeSettings fees;
                fees.show();
            } else if (cmd == "exit" || cmd == "quit") {
                break;
            }
        } catch (...) {
            cout << "Error: Invalid command.\n";
        }
    }
    return 0;
}
