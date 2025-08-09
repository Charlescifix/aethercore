# AEGOCAP DeFi System

A secure cryptocurrency investment platform built with FastAPI, PostgreSQL, and advanced security features.

## 🔧 System Requirements

- Python 3.12+
- PostgreSQL 12+
- Node.js (for frontend assets)
- Environment variables configured in `.env`

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd aether_core

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your database credentials and secrets
```

### 2. Database Setup

```bash
# Initialize database tables
python -c "from data_layer.init_db import init_models; import asyncio; asyncio.run(init_models())"

# Run migrations if needed
python migrate_db.py
```

### 3. Run the Application

```bash
# Start the FastAPI server
uvicorn main_node:app --host 0.0.0.0 --port 8000 --reload
```

## 🌐 Local Testing Links

### **Main Application URLs**

| Page | URL | Description |
|------|-----|-------------|
| **Landing Page** | [http://localhost:8000/](http://localhost:8000/) | Main homepage |
| **User Registration** | [http://localhost:8000/register](http://localhost:8000/register) | Create new account |
| **User Login** | [http://localhost:8000/login](http://localhost:8000/login) | User authentication |
| **Admin Login** | [http://localhost:8000/admin/login](http://localhost:8000/admin/login) | Admin panel access |

### **User Onboarding Flow** (Requires Login)

| Step | URL | Description |
|------|-----|-------------|
| **Step 1: Overview** | [http://localhost:8000/structure-glimpse](http://localhost:8000/structure-glimpse) | Business model overview |
| **Step 2: Expectations** | [http://localhost:8000/expectation-frame](http://localhost:8000/expectation-frame) | Risk disclaimers |
| **Step 3: Plan Selection** | [http://localhost:8000/plan-choice](http://localhost:8000/plan-choice) | Investment plan selection |
| **Step 4: Deposit Gateway** | [http://localhost:8000/deposit-gateway](http://localhost:8000/deposit-gateway) | USDT deposit instructions |
| **Step 5: Deposit Confirmation** | [http://localhost:8000/confirm-deposit](http://localhost:8000/confirm-deposit) | Submit transaction details |
| **Step 6: Dashboard** | [http://localhost:8000/vision-frame](http://localhost:8000/vision-frame) | User dashboard |

### **Admin Panel URLs** (Requires Admin Login)

| Function | URL | Description |
|----------|-----|-------------|
| **Pending Deposits** | [http://localhost:8000/admin/pending-verifications](http://localhost:8000/admin/pending-verifications) | Review pending deposits |
| **Verified Deposits** | [http://localhost:8000/admin/verified-deposits](http://localhost:8000/admin/verified-deposits) | View approved deposits |

### **API Health Checks**

| Endpoint | URL | Description |
|----------|-----|-------------|
| **App Status** | [http://localhost:8000/health](http://localhost:8000/health) | Application health check |
| **Database Status** | [http://localhost:8000/db-health](http://localhost:8000/db-health) | Database connectivity |

## 🔐 Security Features

### **Implemented Security Measures**

- ✅ **Multi-factor Authentication** (Password + TOTP)
- ✅ **Session Management** with secure cookies
- ✅ **Input Validation** and sanitization
- ✅ **Rate Limiting** protection
- ✅ **Duplicate Transaction** prevention
- ✅ **SQL Injection** protection (SQLAlchemy ORM)
- ✅ **XSS Protection** with CSP headers
- ✅ **CSRF Protection** with session tokens
- ✅ **Audit Logging** for all security events
- ✅ **Password Hashing** with bcrypt
- ✅ **Enum Validation** for database integrity

### **Blockchain Integration**

- ✅ **TRON Network** support (TRC20 USDT)
- ✅ **Transaction Hash** format validation (64-char hex)
- ✅ **Wallet Address** validation (T + 33 chars)
- ✅ **TronScan Links** for manual verification
- ⚠️ **Manual Verification** (no automatic blockchain API)

## 📋 Testing Scenarios

### **User Registration & Login**
1. Create account at `/register`
2. Set up 2FA with authenticator app
3. Login at `/login` with email + password + OTP

### **Investment Flow**
1. Complete onboarding steps 1-3
2. Select investment plan (1000-4500 or 4501-9000 USDT)
3. Send USDT to provided wallet address
4. Submit transaction details at `/confirm-deposit`
5. Wait for admin verification

### **Admin Operations**
1. Login as admin
2. Review pending deposits at `/admin/pending-verifications`
3. Verify transactions on TronScan
4. Approve/reject deposits

### **Security Testing**
1. **Duplicate TX Test**: Try submitting same transaction hash twice
2. **Rate Limiting**: Rapid form submissions
3. **Input Validation**: Invalid formats, SQL injection attempts
4. **Session Security**: Cookie tampering, session replay

## 🐛 Known Issues & Limitations

### **Missing Features**
- ❌ **Automatic Blockchain Verification** - relies on manual admin verification
- ❌ **Email Notifications** - deposit status updates not sent
- ❌ **Transaction History** - no user transaction log
- ❌ **Withdrawal System** - no user withdrawal functionality

### **Security Enhancements Needed**
- 🔄 **TronScan API Integration** for automatic transaction verification
- 🔄 **Balance Verification** against claimed amounts
- 🔄 **Transaction Confirmation** checks (minimum confirmations)
- 🔄 **Address Ownership** verification

## 📁 Project Structure

```
aether_core/
├── auth_control/          # Authentication & authorization
├── data_layer/           # Database models & connections
├── middleware_layer/     # Security middleware
├── monitor_unit/         # Logging & monitoring
├── pulse_hub/           # Main application routes
├── templates/           # HTML templates
├── static/             # CSS, JS, images
├── main_node.py        # FastAPI application entry point
└── requirements.txt    # Python dependencies
```

## 🔧 Configuration

### **Required Environment Variables**
```env
DATABASE_URL=postgresql+asyncpg://user:password@localhost/database
SESSION_SECRET=your-super-secret-session-key
USDT_WALLET_ADDRESS=TJqCov92oYGuxjapf7jzFqDyk4vrSxm1Xc
FRONTEND_URL=http://localhost:3000
```

### **Optional Configuration**
```env
LOG_LEVEL=INFO
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600
MAX_UPLOAD_SIZE=10485760
```

## 🧪 Development Tools

### **Database Management**
```bash
# Check database enums
python check_enums.py

# Verify user data
python check_user_data.py

# Test deposit flow
python test_deposit_flow.py

# Debug login issues  
python debug_login.py
```

### **Testing Scripts**
```bash
# Test OTP functionality
python test_otp.py

# Test login fix
python test_login_fix.py

# Database health check
python -c "from data_layer.init_db import init_models; print('DB OK')"
```

## 📊 Monitoring & Logs

- **Security Events**: `logs/security_audit.log`
- **Application Logs**: Console output with structured logging
- **Database Events**: SQLAlchemy query logging (when `echo=True`)

## 🤝 Contributing

1. Follow secure coding practices
2. Validate all user inputs
3. Add audit logging for security events
4. Test authentication flows thoroughly
5. Document security implications

## 📞 Support

For technical issues or security concerns:
- Check application logs for detailed error messages
- Verify database connectivity and migrations
- Ensure all environment variables are properly configured
- Test with minimal viable data first

---

**⚠️ Security Notice**: This application handles financial transactions. Always run security audits and penetration testing before production deployment.