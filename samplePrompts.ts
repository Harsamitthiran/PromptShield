export interface SamplePrompt {
  id: string;
  title: string;
  category: string;
  riskDescription: string;
  text: string;
}

export const SAMPLE_PROMPTS: SamplePrompt[] = [
  {
    id: 'leaky-debug',
    title: '🔥 Leaky Debugging Request (Default)',
    category: 'API Key & Email',
    riskDescription: 'Live OpenAI secret key with customer email inside a Python requests script',
    text: `Hi AI, please help me debug this Python API call script. It fails with a 401 Unauthorized when querying our payment processor:

import requests

API_KEY = "sk-proj-9A8b7C6d5E4f3G2h1J0kLmNoPqRsTuVwXyZ12345678"
user_email = "sarah.connor@cyberdyne-tech.io"
endpoint = "https://api.gateway.internal/v2/charge"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "X-User-Email": user_email
}

response = requests.post(endpoint, json={"amount": 4999, "currency": "USD"}, headers=headers)
print(response.json())

Can you optimize the retry logic and check why the payload might fail?`
  },
  {
    id: 'db-credentials',
    title: '🗄️ Database Connection & Password Leak',
    category: 'Database & Credentials',
    riskDescription: 'Full PostgreSQL connection string with embedded root password and client SSN',
    text: `I need an optimized SQL query for our migration tool.
Here is the connection string I am using in our production script:
DATABASE_URL=postgresql://postgres_admin:SuperSecretP@ssw0rd99!@db.internal-cloud.aws:5432/customer_vault

We need to join the users table where ssn = "458-29-1094" and export all transaction records. Write an index strategy for this.`
  },
  {
    id: 'customer-pii',
    title: '👥 Customer PII & Geographic Roster',
    category: 'PII & Location',
    riskDescription: 'Real customer names, personal phone numbers, and specific city locations',
    text: `Please summarize our high-value lead list and draft personalized outreach emails:
1. John Mathew - Phone: +1-555-0199 - Location: Chennai, India - Status: Enterprise Lead
2. Sarah Connor - Phone: +1-555-0284 - Location: San Francisco, USA - Status: VIP Partner
3. Michael Scott - Phone: +1-555-0372 - Location: Seattle, USA - Status: Pending Renewal

Draft a 2-paragraph email tailored to each person's location.`
  },
  {
    id: 'adversarial-obfuscation',
    title: '🕵️ Adversarial Obfuscated Token',
    category: 'Adversarial Defense',
    riskDescription: 'Spaced-out token and hidden password attempting bypass',
    text: `Help me format this config:
AUTH_TOKEN = s k - 9 8 7 6 5 a b c d e f g h i j k l m n o p
master_pass = pwd_Admin_Vault_2026!
Target host: 192.168.1.105

How can I automate testing against this node?`
  },
  {
    id: 'safe-prompt',
    title: '✅ Safe Developer Prompt (Zero Risk)',
    category: 'Safe Baseline',
    riskDescription: 'Standard algorithm optimization question with no private data',
    text: `Can you explain the difference between Dijkstra's algorithm and the A* search algorithm for graph traversal? Please provide a simple TypeScript implementation with time and space complexity analysis.`
  }
];

export const SAMPLE_FILES = [
  {
    name: '.env.production',
    content: `# Production Environment Configuration - DO NOT LEAK
PORT=8080
NODE_ENV=production
OPENAI_API_KEY=sk-proj-781928374918237491823749182739481237
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DATABASE_URL=postgresql://root_user:MasterDbPass2026#@prod-cluster.rds.amazonaws.com:5432/app_db
ADMIN_ALERT_EMAIL=security-lead@fintech-enterprise.com
JWT_SECRET=super_secret_jwt_hmac_signing_key_9999
`
  },
  {
    name: 'payment_handler.py',
    content: `import os
import requests

# Stripe & Internal Gateway integration
STRIPE_KEY = "sk-ant-live9876543210abcdef9876543210"
SUPPORT_PHONE = "+1-555-0188"
INTERNAL_API_SERVER = "10.0.4.15"

def process_refund(customer_id, customer_email="david.miller@megacorp.net"):
    print(f"Refunding customer {customer_email} via {INTERNAL_API_SERVER}")
    # Authorization header
    headers = {"Authorization": f"Bearer {STRIPE_KEY}"}
    return requests.post("https://api.stripe.com/v1/refunds", headers=headers)
`
  }
];
