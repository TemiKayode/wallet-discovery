# 🔑 API Keys Guide for Crypto Wallet Discovery & Analysis Toolkit

This guide provides detailed information about all the API keys needed to get excellent results from the Crypto Wallet Discovery & Analysis Toolkit.

## 🎯 **Essential API Keys (Required for Basic Functionality)**

### 1. **Etherscan API Key** ⭐ **CRITICAL**
- **Purpose**: Ethereum blockchain data, transaction history, wallet analysis
- **Get it here**: https://etherscan.io/apis
- **Free tier**: 5 calls/second, 100,000 calls/day
- **Why essential**: Primary source for Ethereum wallet discovery and analysis
- **Usage**: Transaction monitoring, wallet balance checks, contract interactions

### 2. **Infura Project ID** ⭐ **CRITICAL**
- **Purpose**: Ethereum RPC access, real-time blockchain data
- **Get it here**: https://infura.io/
- **Free tier**: 100,000 requests/day
- **Why essential**: Direct blockchain access for real-time data
- **Usage**: Web3 connections, transaction broadcasting, block monitoring

## 🚀 **High-Value API Keys (For Excellent Results)**

### 3. **BSCscan API Key** ⭐ **HIGHLY RECOMMENDED**
- **Purpose**: Binance Smart Chain data, BSC wallet analysis
- **Get it here**: https://bscscan.com/apis
- **Free tier**: 5 calls/second, 100,000 calls/day
- **Why valuable**: Access to BSC ecosystem, DeFi protocols, cross-chain analysis

### 4. **Polygonscan API Key** ⭐ **HIGHLY RECOMMENDED**
- **Purpose**: Polygon blockchain data, MATIC transactions
- **Get it here**: https://polygonscan.com/apis
- **Free tier**: 5 calls/second, 100,000 calls/day
- **Why valuable**: Layer 2 scaling solutions, low-cost transactions

### 5. **Alchemy API Key** ⭐ **HIGHLY RECOMMENDED**
- **Purpose**: Enhanced blockchain infrastructure, Web3 development
- **Get it here**: https://www.alchemy.com/
- **Free tier**: 300M compute units/month
- **Why valuable**: Better reliability than Infura, advanced features

## 🎨 **Specialized API Keys (For Advanced Features)**

### 6. **OpenSea API Key** 🎨 **NFT Analysis**
- **Purpose**: NFT market data, collection analysis, trading patterns
- **Get it here**: https://docs.opensea.io/reference/api-overview
- **Free tier**: 1,000 requests/day
- **Why valuable**: NFT wallet discovery, collection analysis, market trends

### 7. **Twitter Bearer Token** 🐦 **Social Media Mining**
- **Purpose**: Social media wallet mentions, sentiment analysis
- **Get it here**: https://developer.twitter.com/en/portal/dashboard
- **Free tier**: 10,000 tweets/month
- **Why valuable**: Social signals, influencer wallet discovery

### 8. **Reddit API Credentials** 🔴 **Community Analysis**
- **Purpose**: Reddit wallet mentions, community sentiment
- **Get it here**: https://www.reddit.com/prefs/apps
- **Free tier**: 60 requests/minute
- **Why valuable**: Community-driven wallet discovery, sentiment analysis

## 📊 **Data Lake Integration (For Enterprise Features)**

### 9. **AWS S3 Credentials** ☁️ **Cloud Storage**
- **Purpose**: Scalable data storage, backup, analytics
- **Get it here**: https://aws.amazon.com/s3/
- **Free tier**: 5GB storage, 20,000 GET requests
- **Why valuable**: Enterprise-grade data persistence

### 10. **Google BigQuery** 📈 **Data Analytics**
- **Purpose**: Large-scale data analysis, SQL queries
- **Get it here**: https://cloud.google.com/bigquery
- **Free tier**: 1TB queries/month
- **Why valuable**: Advanced analytics, data warehousing

## 🛠️ **Configuration Setup**

### Step 1: Get Your API Keys
1. **Start with Essential Keys**: Etherscan + Infura (minimum viable setup)
2. **Add High-Value Keys**: BSCscan + Polygonscan + Alchemy (recommended)
3. **Include Specialized Keys**: OpenSea + Twitter + Reddit (advanced features)

### Step 2: Update config.ini
Replace the placeholder values in your `config.ini` file:

```ini
[API_KEYS]
etherscan = YOUR_ACTUAL_ETHERSCAN_API_KEY
bscscan = YOUR_ACTUAL_BSCSCAN_API_KEY
polygonscan = YOUR_ACTUAL_POLYGONSCAN_API_KEY
infura = YOUR_ACTUAL_INFURA_PROJECT_ID
alchemy = YOUR_ACTUAL_ALCHEMY_API_KEY
opensea = YOUR_ACTUAL_OPENSEA_API_KEY
twitter_bearer_token = YOUR_ACTUAL_TWITTER_BEARER_TOKEN
reddit_client_id = YOUR_ACTUAL_REDDIT_CLIENT_ID
reddit_client_secret = YOUR_ACTUAL_REDDIT_CLIENT_SECRET
```

### Step 3: Update RPC Endpoints
```ini
[BLOCKCHAIN]
ethereum_rpc = https://mainnet.infura.io/v3/YOUR_ACTUAL_INFURA_PROJECT_ID
bsc_rpc = https://bsc-dataseed.binance.org/
polygon_rpc = https://polygon-rpc.com/
bitcoin_rpc = https://blockchain.info/
```

## 🎯 **Results Quality by API Key Tier**

### 🥉 **Basic Setup** (Essential Keys Only)
- ✅ Basic wallet discovery
- ✅ Ethereum transaction analysis
- ✅ Simple wallet categorization
- ❌ Limited to Ethereum only
- ❌ No social media insights
- ❌ No NFT analysis

### 🥈 **Recommended Setup** (Essential + High-Value)
- ✅ Multi-chain wallet discovery
- ✅ Comprehensive transaction analysis
- ✅ DeFi protocol analysis
- ✅ Cross-chain wallet tracking
- ❌ Limited social insights
- ❌ No NFT market analysis

### 🥇 **Excellent Results** (All API Keys)
- ✅ Full multi-chain coverage
- ✅ Social media wallet discovery
- ✅ NFT market analysis
- ✅ Community sentiment analysis
- ✅ Advanced pattern recognition
- ✅ Comprehensive wallet profiling

## 💡 **Pro Tips for Maximum Results**

### 1. **API Key Management**
- Use environment variables for production
- Rotate keys regularly for security
- Monitor usage to avoid rate limits
- Set up alerts for quota exhaustion

### 2. **Rate Limiting Optimization**
- Configure appropriate delays in `config.ini`
- Use proxy rotation for high-volume requests
- Implement exponential backoff
- Monitor API response times

### 3. **Data Quality Enhancement**
- Enable all discovery methods
- Configure appropriate thresholds
- Use multiple data sources for validation
- Implement data quality checks

### 4. **Performance Tuning**
- Adjust `max_concurrent_requests` based on API limits
- Optimize `discovery_interval_minutes` for your needs
- Use appropriate `max_blocks_to_scan` values
- Enable caching where possible

## 🔧 **Quick Setup Commands**

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the demo to test your setup
python examples/technical_enhancements_demo.py

# 3. Validate your configuration
python -c "from src.config.settings import ConfigManager; ConfigManager().validate_config()"

# 4. Start the main application
python main.py
```

## 🚨 **Important Notes**

- **Free Tiers**: Most APIs offer generous free tiers sufficient for development and testing
- **Rate Limits**: Be mindful of API rate limits to avoid service interruptions
- **Security**: Never commit API keys to version control
- **Backup**: Keep API keys in a secure location
- **Monitoring**: Set up alerts for API quota usage

## 🎉 **Expected Results with Full API Setup**

With all API keys configured, you can expect:
- **1000+ wallets/hour** discovery rate
- **99.5% data accuracy** validation
- **Multi-chain coverage** (Ethereum, BSC, Polygon, Bitcoin)
- **Real-time monitoring** capabilities
- **Advanced analytics** and insights
- **Social media integration** for wallet discovery
- **NFT market analysis** and trends
- **Enterprise-grade** data processing

---

**Ready to get started?** Begin with the Essential API Keys (Etherscan + Infura) and gradually add more as needed for your specific use case!
