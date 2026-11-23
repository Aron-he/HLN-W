import { createHash, createHmac } from 'node:crypto'
import { openAsBlob } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import updateFeed from '../electron/app-update-feed.cjs'

const { compareVersions, fileDigest, maxFeedBytes, readRelease, releaseAssetUrl, releaseChannel } = updateFeed
const uploadOrigins = {
  z0: 'https://up-z0.qiniup.com',
  z1: 'https://up-z1.qiniup.com',
  z2: 'https://up-z2.qiniup.com',
  'cn-east-2': 'https://up-cn-east-2.qiniup.com',
}

const safeBase64 = value => value.toString('base64').replaceAll('+', '-').replaceAll('/', '_')

function uploadToken(config, key, insertOnly) {
  const policy = safeBase64(Buffer.from(JSON.stringify({
    scope: `${config.bucket}:${key}`,
    deadline: Math.floor(Date.now() / 1000) + 3600,
    insertOnly: Number(insertOnly),
  })))
  const signature = safeBase64(createHmac('sha1', config.secretKey).update(policy).digest())
  return `${config.accessKey}:${signature}:${policy}`
}

async function upload(config, source, file, mimeType, insertOnly) {
  const key = 'stable/' + file
  const body = new FormData()
  body.set('key', key)
  body.set('token', uploadToken(config, key, insertOnly))
  body.set('file', await openAsBlob(source, { type: mimeType }), file)
  const response = await fetch(config.upload, {
    method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(15 * 60_000),
  })
  const status = response.status
  await response.body?.cancel()
  if (status !== 200 && !(insertOnly && status === 614)) throw new Error(`Qiniu upload returned HTTP ${status}.`)
}

async function readPublicManifest(channel) {
  const response = await fetch(channel.url, {
    redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(30_000),
  })
  if (!response.ok || !response.body) {
    await response.body?.cancel()
    if (response.status === 404) return null
    throw new Error(`Mirror manifest returned HTTP ${response.status}.`)
  }
  const chunks = []
  let length = 0
  for await (const chunk of response.body) {
    length += chunk.length
    if (length > maxFeedBytes) throw new Error('Mirror manifest exceeded its size limit.')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}

async function verifyPublicArchive(channel, release) {
  const url = releaseAssetUrl(release.file, release.version, channel.url)
  for (let attempt = 0; attempt < 6; attempt++) {
    const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10 * 60_000) })
    if (response.status === 404) {
      await response.body?.cancel()
      await delay(3000)
      continue
    }
    if (!response.ok || !response.body) {
      await response.body?.cancel()
      throw new Error(`Mirror archive returned HTTP ${response.status}.`)
    }
    const hash = createHash('sha256')
    let size = 0
    for await (const chunk of response.body) {
      size += chunk.length
      if (size > release.size) throw new Error('Public archive exceeded its signed size.')
      hash.update(chunk)
    }
    if (size !== release.size || hash.digest('hex') !== release.sha256) throw new Error('Mirror archive failed SHA-256 verification.')
    return
  }
  throw new Error('The uploaded archive is not available at the mirror URL.')
}

async function publish(stagedRoot, publicKeyPath, config) {
  const channel = releaseChannel({ feed: config.feed, publicKey: await readFile(publicKeyPath, 'utf8') })
  const feedPath = join(stagedRoot, 'stable', 'latest.json')
  const manifest = await readFile(feedPath)
  const release = readRelease(JSON.parse(manifest), channel)
  const prior = await readPublicManifest(channel)
  if (prior) {
    const lastRelease = readRelease(JSON.parse(prior), channel)
    const order = compareVersions(release.version, lastRelease.version)
    if (order < 0 || (order === 0 && release.sha256 !== lastRelease.sha256)) {
      throw new Error('The mirror already serves a newer or conflicting release.')
    }
  }
  const alreadyCurrent = prior?.equals(manifest) === true
  if (alreadyCurrent && !config.verifyWrite) {
    console.log(`Qiniu mirror already current: ${release.version}`)
    return
  }
  const archive = join(stagedRoot, 'stable', release.file)
  if (await fileDigest(archive) !== release.sha256) throw new Error('Staged archive failed SHA-256 verification.')
  await upload(config, archive, release.file, 'application/zip', true)
  await verifyPublicArchive(channel, release)
  await upload(config, feedPath, 'latest.json', 'application/json', false)
  if (!(await readPublicManifest(channel))?.equals(manifest)) throw new Error('Mirror manifest is not current. Check the CDN cache settings.')
  if (alreadyCurrent) console.log(`Qiniu mirror write verified: ${release.version}`)
  else console.log(`Qiniu mirror published: ${release.version}`)
}

const [,, root, keyFile] = process.argv
const { QINIU_BUCKET: bucket, QINIU_REGION: region, QINIU_MIRROR_FEED: feed,
  QINIU_ACCESS_KEY: accessKey, QINIU_SECRET_KEY: secretKey, QINIU_VERIFY_WRITE: verifyWrite } = process.env
const origin = Object.hasOwn(uploadOrigins, region) ? uploadOrigins[region] : undefined
if (!root || !keyFile || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(bucket ?? '') || !origin || !feed || !accessKey || !secretKey) {
  console.error('Set the Qiniu region, bucket, HTTPS mirror feed, upload credentials and staged release paths.')
  process.exitCode = 1
} else {
  await publish(root, keyFile, { bucket, feed, accessKey, secretKey, upload: origin, verifyWrite: verifyWrite === '1' }).catch(error => {
    console.error(error.message)
    process.exitCode = 1
  })
}
