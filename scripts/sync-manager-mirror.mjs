import { createWriteStream } from 'node:fs'
import { link, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import updateFeed from '../electron/app-update-feed.cjs'

const githubFeed = 'https://github.com/Aron-he/HLN-W/releases/latest/download/latest.json'
const { allowedRedirect, compareVersions, fileDigest, maxFeedBytes, readRelease, releaseAssetUrl, releaseChannel } = updateFeed

async function fetchFile(url, signal) {
  for (let hop = 0; hop < 5; hop++) {
    const response = await fetch(url, { signal, redirect: 'manual', cache: 'no-store' })
    if (response.ok && response.body) return response.body
    await response.body?.cancel()
    const location = response.headers.get('location')
    if (!location || ![301, 302, 303, 307, 308].includes(response.status)) {
      throw new Error(`HTTP ${response.status} from ${url.hostname}`)
    }
    url = allowedRedirect(url, location)
  }
  throw new Error('Too many update feed redirects.')
}

async function readManifest(channel) {
  const chunks = []
  let length = 0
  for await (const chunk of await fetchFile(channel.url, AbortSignal.timeout(30_000))) {
    length += chunk.length
    if (length > maxFeedBytes) throw new Error('The update manifest is too large.')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}

async function fileInfo(file) {
  try {
    const info = await lstat(file)
    if (!info.isFile()) throw new Error('Expected a regular mirror file.')
    return info
  } catch (error) {
    if (error.code === 'ENOENT') return null
    throw error
  }
}

async function verifyArchive(target, info, release) {
  if (info.size !== release.size || await fileDigest(target) !== release.sha256) {
    throw new Error(`Archive does not match the signed size and SHA-256: ${release.file}`)
  }
}

async function downloadArchive(channel, release, target) {
  const url = releaseAssetUrl(release.file, release.version, channel.url)
  const stalled = new AbortController()
  const deadline = setTimeout(() => stalled.abort(new Error('Archive download stalled.')), 45_000)
  const signal = AbortSignal.any([stalled.signal, AbortSignal.timeout(20 * 60_000)])
  let length = 0
  const sizeLimit = new Transform({
    transform(chunk, _, callback) {
      deadline.refresh()
      length += chunk.length
      if (length > release.size) return callback(new Error('Download exceeded its signed size.'))
      callback(null, chunk)
    },
  })
  try {
    const body = await fetchFile(url, signal)
    await pipeline(body, sizeLimit, createWriteStream(target, { flags: 'wx' }), { signal })
  } finally {
    clearTimeout(deadline)
  }
  await verifyArchive(target, await fileInfo(target), release)
}

async function syncMirror(directory, publicKeyPath, feed) {
  const channel = releaseChannel({ feed, publicKey: await readFile(publicKeyPath, 'utf8') })
  const manifest = await readManifest(channel)
  const release = readRelease(JSON.parse(manifest), channel)

  await mkdir(directory, { recursive: true })
  const root = await realpath(directory)
  const endpoint = join(root, 'stable')
  await mkdir(endpoint, { recursive: true })
  if (await realpath(endpoint) !== endpoint) throw new Error('The stable directory must be inside the mirror root.')
  const latest = join(endpoint, 'latest.json')
  const currentManifest = await fileInfo(latest) ? await readFile(latest) : null
  if (currentManifest) {
    const previous = readRelease(JSON.parse(currentManifest), channel)
    const order = compareVersions(release.version, previous.version)
    if (order < 0) throw new Error(`Refusing to replace ${previous.version} with ${release.version}.`)
    if (order === 0 && (release.sha256 !== previous.sha256 || release.size !== previous.size)) {
      throw new Error(`Version ${release.version} already refers to a different archive.`)
    }
  }

  const archive = join(endpoint, release.file)
  const existing = await fileInfo(archive)
  if (existing) await verifyArchive(archive, existing, release)
  if (existing && currentManifest?.equals(manifest)) {
    console.log(`Mirror already current: ${release.version}`)
    return
  }
  const staging = await mkdtemp(join(root, '.sync-'))
  try {
    if (!existing) {
      const temporaryArchive = join(staging, release.file)
      await downloadArchive(channel, release, temporaryArchive)
      try { await link(temporaryArchive, archive) }
      catch (error) {
        if (error.code !== 'EEXIST') throw error
        await verifyArchive(archive, await fileInfo(archive), release)
      }
    }

    const temporaryManifest = join(staging, 'latest.json')
    await writeFile(temporaryManifest, manifest, { flag: 'wx' })
    await rename(temporaryManifest, latest)
    console.log(`Mirror ready: ${release.version} (${release.size} bytes)`)
  } finally {
    if (await realpath(staging) === staging) await rm(staging, { recursive: true, force: true })
  }
}

const [, , destination, publicKeyPath, feed] = process.argv
if (!destination || !publicKeyPath) {
  console.error('Usage: node scripts/sync-manager-mirror.mjs <mirror-root> <public-key.pem> [feed-url]')
  process.exitCode = 1
} else {
  await syncMirror(resolve(destination), resolve(publicKeyPath), feed || githubFeed).catch(error => {
    console.error(error.message)
    process.exitCode = 1
  })
}
