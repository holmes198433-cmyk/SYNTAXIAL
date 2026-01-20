/*
  All rights reserved 2026 © Syntaxial - Pro Modernis
  Proprietary and confidential. Unauthorized copying, modification, or distribution is strictly prohibited.
*/

// --- OmniGraph DSI Engine Backend Blueprint (Hardened & Env-driven) ---
// Runtime: Node.js

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// --- REQUIRED ENV VARS (set in Railway)
const REQUIRED_ENVS = [
  'DATABASE_URL',
  'HOST',
  'RAILWAY_PUBLIC_DOMAIN',
  'SCOPES',
  'SHOPIFY_API_KEY',
  'SHOPIFY_API_SECRET',
  'SHOPIFY_APP_URL',
  'DSI_MASTER_KEY', // Admin-only bearer token
  'DSI_API_KEY',    // Public/storefront key for client requests
  'SHOPIFY_WEBHOOK_SECRET' // Shopify webhook secret for HMAC verification
];

for (const v of REQUIRED_ENVS) {
  if (!process.env[v]) {
    console.warn(`Warning: environment variable ${v} is not set.`);
  }
}

// In production we expect these to be set; we fail fast for critical ones
if (!process.env.DSI_MASTER_KEY) {
  console.error('DSI_MASTER_KEY is recommended. Set it in your Railway environment.');
  // process.exit(1); // optional strict behavior
}

// Middleware
app.use(helmet());
app.use(cors({ origin: true }));
app.use(bodyParser.json({ verify: rawBodySaver }));

// Rate limiter (basic)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300 // limit each IP to 300 requests per windowMs
});
app.use(limiter);

// Helper to save raw body for webhook verification
function rawBodySaver(req, res, buf, encoding) {
  if (buf && buf.length) {
    req.rawBody = buf.toString(encoding || 'utf8');
  }
}

// --- CONFIGURATION (Environment Variables in production) ---
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || 'shhhhhh_this_is_a_secret_key';
const DSI_API_KEY = process.env.DSI_API_KEY || 'dsi_api_key_for_client_requests';
const DSI_MASTER_KEY = process.env.DSI_MASTER_KEY || null;

// Mock Firestore-like DB for blueprint/demo purposes
const FIRESTORE_MOCK_DB = {
  'default-app-id': {
    jsonLdTemplate: `{
  "@context": "https://schema.org/",
  "@type": "Product",
  "name": "[product.title]",
  "description": "A fully customized, SEO-optimized product.",
  "offers": {
    "@type": "Offer",
    "priceCurrency": "USD",
    "price": "[current_price]"
  },
  "identifier": "[product.metafields.custom.isbn]",
  "_comment_id_1": "// Mapped via OmniGraph Node ID 1",
  "review": { 
    "@type": "AggregateRating",
    "ratingValue_Rule": "IF (review_count > 5 AND average_rating > 4.5 END) THEN [average_rating] ELSE [NULL]"
  },
  "_comment_rule_2": "// Mapped to review with 2 condition(s)."
}`,
    mappings: JSON.stringify([
      { id: 1, source: 'product.metafields.custom.isbn', target: 'identifier', type: 'Text', conditions: [] },
      { id: 2, source: 'average_rating', target: 'review', type: 'Condition', conditions: [
        { field: 'review_count', operator: '>', value: 5, logic: 'AND' },
        { field: 'average_rating', operator: '>', value: 4.5, logic: 'END' }
      ]}
    ])
  }
};

// --- CORE LOGIC: DSI PROCESSOR (unchanged logic, hardened error handling) ---
function evaluateCondition(field, operator, value, data) {
  const dataValue = data[field];
  if (dataValue === undefined) return false;
  switch (operator) {
    case '>':
      return parseFloat(dataValue) > parseFloat(value);
    case '<':
      return parseFloat(dataValue) < parseFloat(value);
    case '==':
      return String(dataValue) === String(value);
    default:
      return false;
  }
}

function processDsiSchema(data, rulesData) {
  if (!rulesData || !rulesData.jsonLdTemplate) {
    throw new Error('Invalid rules data.');
  }

  let jsonString = rulesData.jsonLdTemplate;
  const mappings = JSON.parse(rulesData.mappings || '[]');
  const finalSchema = JSON.parse(jsonString);

  // A. Process Simple Placeholders (deep traversal for safety)
  function traverse(obj) {
    for (const key in obj) {
      if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
      const value = obj[key];
      if (typeof value === 'string' && value.startsWith('[') && value.endsWith(']')) {
        const sourceKey = value.slice(1, -1);
        if (data[sourceKey] !== undefined) {
          obj[key] = data[sourceKey];
        } else {
          delete obj[key];
        }
      } else if (typeof value === 'object' && value !== null) {
        traverse(value);
      }
    }
  }
  traverse(finalSchema);

  // B. Conditional Rules (review example)
  if (finalSchema.review && finalSchema.review.ratingValue_Rule) {
    const mapping = mappings.find(m => m.target === 'review' && m.type === 'Condition');
    if (mapping && mapping.conditions && mapping.conditions.length > 0) {
      let isMet = true;
      for (const condition of mapping.conditions) {
        const result = evaluateCondition(condition.field, condition.operator, condition.value, data);
        if (!result) { isMet = false; break; }
      }
      if (isMet) {
        const source = mapping.source;
        finalSchema.review.ratingValue = data[source] || '5.0';
      } else {
        delete finalSchema.review;
      }
    }
    if (finalSchema.review) delete finalSchema.review.ratingValue_Rule;
  }

  for (const key in finalSchema) {
    if (key.startsWith('_comment')) delete finalSchema[key];
  }

  return JSON.stringify(finalSchema, null, 2);
}

// --- ENDPOINTS ---

// Pulse endpoint for monitoring
app.get('/api/v1/dsi/pulse', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// DSI Schema endpoint (storefront-facing)
app.post('/api/dsi/schema', async (req, res) => {
  try {
    // API Key Validation: Allow storefronts to use header X-DSI-API-KEY
    const clientApiKey = req.headers['x-dsi-api-key'] || req.headers['x-dsi-api-key'.toLowerCase()];
    if (clientApiKey !== DSI_API_KEY) {
      return res.status(401).json({ error: 'Unauthorized: Invalid API Key' });
    }

    const { appId, productData } = req.body;
    if (!appId || !productData) {
      return res.status(400).json({ error: 'Missing required parameters (appId or productData)' });
    }

    const rulesData = FIRESTORE_MOCK_DB[appId] || FIRESTORE_MOCK_DB['default-app-id'];
    if (!rulesData) {
      console.warn(`Rules not found for App ID: ${appId}`);
      return res.status(404).json({ error: 'Mapping rules not deployed for this app.' });
    }

    const finalJsonLd = processDsiSchema(productData, rulesData);
    res.json({ schema: finalJsonLd, timestamp: new Date().toISOString() });

  } catch (e) {
    console.error('DSI Processing Error:', e);
    res.status(500).json({ error: 'Internal DSI processing failed.' });
  }
});

// Webhook endpoint with HMAC verification — uses raw body saved earlier
app.post('/webhook/rules_update', (req, res) => {
  const hmac = req.headers['x-shopify-hmac-sha256'];
  const body = req.rawBody || '';

  const generatedHash = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(body)
    .digest('base64');

  if (generatedHash !== hmac) {
    console.warn('Webhook received with invalid HMAC signature.');
    return res.status(401).send('Invalid signature.');
  }

  console.log(`Webhook received and validated for shop: ${req.headers['x-shopify-shop-domain']}`);
  // Placeholder: trigger rule cache invalidation or datastore refresh
  res.status(200).send('Webhook processed successfully.');
});

// Admin-only endpoint example (requires DSI_MASTER_KEY bearer token)
app.post('/admin/reload-rules', (req, res) => {
  const auth = req.headers['authorization'] || '';
  if (!DSI_MASTER_KEY || !auth.startsWith('Bearer ') || auth.slice(7) !== DSI_MASTER_KEY) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  // Placeholder for admin operations
  res.json({ status: 'reloaded' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`DSI Engine is running on port ${PORT}`);
  console.log('Ensure environment variables are configured in Railway before production use.');
});                                                               
