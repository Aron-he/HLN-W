const { createHash, createPublicKey, verify } = require('node:crypto')
const { createReadStream } = require('node:fs')

const product = 'HLN-W'
const platform = 'win-x64'
const maxFeedBytes = 64 * 1024
const maxArchiveBytes = 1024 ** 3
const versionPattern = /^(0|[1-9]\d{0,7})\.(0|[1-9]\d{0,7})\.(0|[1-9]\d{0,7})$/

function archiveName(version) {
  if (typeof version !== 'string' || !versionPattern.test(version)) throw new Error('Invalid release version.')
  return `${product}-${version}-${platform}.zip`
}

function compareVersions(left, right) {
  archiveName(left)
  archiveName(right)
  const parts = right.split('.').map(Number)
  return left.split('.').map((part, index) => Number(part) - parts[index]).find(Boolean) ?? 0
}

function feedUrl(value) {
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search
    || !url.pathname.endsWith('/latest.json')) throw new Error('Use an HTTPS latest.json URL.')
  return url
}

function releaseChannel(config) {
  const publicKey = createPublicKey(config.publicKey)
  const mirrors = config.mirrors ?? []
  if (publicKey.asymmetricKeyType !== 'ed25519' || !Array.isArray(mirrors) || mirrors.length > 2) {
    throw new Error('Use an Ed25519 public key and at most two mirrors.')
  }
  const url = feedUrl(config.feed)
  const sources = [...new Set([url.href, ...mirrors.map(mirror => feedUrl(mirror).href)])].map(source => new URL(source))
  return { url, mirrors: sources.slice(1), publicKey }
}

function githubReleasePath(url) {
  return url.origin === 'https://github.com' && /^\/[^/]+\/[^/]+\/releases\/(latest\/download|download\/[^/]+)\//.test(url.pathname)
}

function allowedRedirect(source, location) {
  const target = new URL(location, source)
  if (target.protocol !== 'https:' || target.username || target.password) throw new Error('Untrusted update redirect.')
  if (target.origin === source.origin) return target
  if (githubReleasePath(source) && ['https://release-assets.githubusercontent.com', 'https://objects.githubusercontent.com'].includes(target.origin)) return target
  throw new Error('Untrusted update redirect.')
}

function releaseAssetUrl(file, version, feed) {
  const url = new URL(file, feed)
  if (githubReleasePath(url)) url.pathname = url.pathname.replace('/releases/latest/download/', `/releases/download/v${version}/`)
  return url
}

function readRelease(envelope, channel) {
  if (typeof envelope.payload !== 'string' || typeof envelope.signature !== 'string') {
    throw new Error('Invalid release envelope.')
  }
  const payload = Buffer.from(envelope.payload, 'base64')
  const signature = Buffer.from(envelope.signature, 'base64')
  if (signature.length !== 64 || !verify(null, payload, channel.publicKey, signature)) {
    throw new Error('Invalid release signature.')
  }
  const release = JSON.parse(payload.toString('utf8'))
  if (release.schema !== 1 || release.product !== product || release.platform !== platform
    || release.file !== archiveName(release.version) || !Number.isSafeInteger(release.size)
    || release.size < 1 || release.size > maxArchiveBytes || typeof release.sha256 !== 'string'
    || !/^[a-f0-9]{64}$/.test(release.sha256)) throw new Error('Invalid release metadata.')
  return release
}

async function fileDigest(file) {
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(file)) hash.update(chunk)
  return hash.digest('hex')
}

module.exports = { product, platform, maxFeedBytes, maxArchiveBytes, archiveName, compareVersions, releaseChannel, allowedRedirect, releaseAssetUrl, readRelease, fileDigest }
