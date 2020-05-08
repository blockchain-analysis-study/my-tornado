const fs = require('fs')
const assert = require('assert')
const { bigInt } = require('snarkjs')
const crypto = require('crypto')
const circomlib = require('circomlib')
const merkleTree = require('./lib/MerkleTree')
const Web3 = require('web3')
const buildGroth16 = require('websnark/src/groth16')
const websnarkUtils = require('websnark/src/utils')
const { toWei } = require('web3-utils')

let web3, contract, netId, circuit, proving_key, groth16
const MERKLE_TREE_HEIGHT = 20
const RPC_URL = 'https://kovan.infura.io/v3/0279e3bdf3ee49d0b547c643c2ef78ef'
const PRIVATE_KEY = 'ad5b6eb7ee88173fa43dedcff8b1d9024d03f6307a1143ecf04bea8ed40f283f' // 0x94462e71A887756704f0fb1c0905264d487972fE
const CONTRACT_ADDRESS = '0xD6a6AC46d02253c938B96D12BE439F570227aE8E'
const AMOUNT = '1'
// CURRENCY = 'ETH'

/** Generate random number of specified byte length */
const rbigint = nbytes => bigInt.leBuff2int(crypto.randomBytes(nbytes))

/** Compute pedersen hash */
const pedersenHash = data => circomlib.babyJub.unpackPoint(circomlib.pedersenHash.hash(data))[0]

/** BigNumber to hex string of specified length */
const toHex = (number, length = 32) => '0x' + (number instanceof Buffer ? number.toString('hex') : bigInt(number).toString(16)).padStart(length * 2, '0')

/**
 * Create deposit object from secret and nullifier
 *
 * 根据 secret 和 nullifier 生成质押信息
 *
 * secret: 一个秘钥, 只有持有秘钥的人才可以花费当前 质押的note
 * nullifier: 生成当前票据时, 已经消耗了的 UTXO 后产生的作废的信息
 */
function createDeposit(nullifier, secret) {
  let deposit = { nullifier, secret }

  // 生成 预处理信息
  deposit.preimage = Buffer.concat([deposit.nullifier.leInt2Buff(31), deposit.secret.leInt2Buff(31)])

  // 生成一个承诺 pedersenHash(nullifier, secret)
  deposit.commitment = pedersenHash(deposit.preimage)
  // 生成 已作废信息的Hash (防止双花的) pedersenHash(nullifier)
  deposit.nullifierHash = pedersenHash(deposit.nullifier.leInt2Buff(31))
  return deposit
}

/**
 * Make an ETH deposit
 *
 * 发起 ETH 质押
 */
async function deposit() {

  // 构建质押入参结构
  // 具备 commitment (承诺) 和 nullifierHash
  const deposit = createDeposit(rbigint(31), rbigint(31))
  console.log('Sending deposit transaction...')

  // 发起 tx ,提交一个 commitment 和 ETH 质押到 Tornado 合约
  const tx = await contract.methods.deposit(toHex(deposit.commitment)).send({ value: toWei(AMOUNT), from: web3.eth.defaultAccount, gas:2e6 })
  console.log(`https://kovan.etherscan.io/tx/${tx.transactionHash}`)

  // 构造 票据信息 并返回
  return `tornado-eth-${AMOUNT}-${netId}-${toHex(deposit.preimage, 62)}`
}

/**
 * Do an ETH withdrawal
 * @param note Note to withdraw
 * @param recipient Recipient address
 */
async function withdraw(note, recipient) {
  // 根据票据 解析出 deposit 实体
  const deposit = parseNote(note)
  // 生成 交易的入参args 和 snark的proof
  const { proof, args } = await generateSnarkProof(deposit, recipient)
  console.log('Sending withdrawal transaction...')

  // 发起提款 交易
  const tx = await contract.methods.withdraw(proof, ...args).send({ from: web3.eth.defaultAccount, gas: 1e6 })
  console.log(`https://kovan.etherscan.io/tx/${tx.transactionHash}`)
}

/**
 * Parses Tornado.cash note
 * @param noteString the note
 */
//
// 解析 note， 得到 deposit 结构
function parseNote(noteString) {
  const noteRegex = /tornado-(?<currency>\w+)-(?<amount>[\d.]+)-(?<netId>\d+)-0x(?<note>[0-9a-fA-F]{124})/g
  const match = noteRegex.exec(noteString)

  // we are ignoring `currency`, `amount`, and `netId` for this minimal example
  const buf = Buffer.from(match.groups.note, 'hex')
  const nullifier = bigInt.leBuff2int(buf.slice(0, 31))
  const secret = bigInt.leBuff2int(buf.slice(31, 62))
  return createDeposit(nullifier, secret)
}

/**
 * Generate merkle tree for a deposit.
 * Download deposit events from the contract, reconstructs merkle tree, finds our deposit leaf
 * in it and generates merkle proof
 * @param deposit Deposit object
 */
// 根据 deposit 生成 merkle tree
//
async function generateMerkleProof(deposit) {
  console.log('Getting contract state...')
  const events = await contract.getPastEvents('Deposit', { fromBlock: 0, toBlock: 'latest' })
  const leaves = events
    .sort((a, b) => a.returnValues.leafIndex - b.returnValues.leafIndex) // Sort events in chronological order
    .map(e => e.returnValues.commitment)

  // 构建一颗 merkle tree
  const tree = new merkleTree(MERKLE_TREE_HEIGHT, leaves) // HEIGHT: 20, leaves: 叶子

  // Find current commitment in the tree
  // 在 tree 中找到当前的承诺
  let depositEvent = events.find(e => e.returnValues.commitment === toHex(deposit.commitment))

  // 找到,则拿索引; 找不到,则返回 -1
  let leafIndex = depositEvent ? depositEvent.returnValues.leafIndex : -1

  // Validate that our data is correct (optional)
  //
  // 验证我们的数据正确（可选）

  // 校验 root
  const isValidRoot = await contract.methods.isKnownRoot(toHex(await tree.root())).call()
  // 校验 nullifierHash 是否已花费
  const isSpent = await contract.methods.isSpent(toHex(deposit.nullifierHash)).call()
  assert(isValidRoot === true, 'Merkle tree is corrupted')
  assert(isSpent === false, 'The note is already spent')
  assert(leafIndex >= 0, 'The deposit is not found in the tree')

  // Compute merkle proof of our commitment
  // 计算我们的承诺的 merkle proof
  return await tree.path(leafIndex)
}

/**
 * Generate SNARK proof for withdrawal
 * @param deposit Deposit object
 * @param recipient Funds recipient
 */
//
// 生成 snark 证明
async function generateSnarkProof(deposit, recipient) {
  // Compute merkle proof of our commitment
  const { root, path_elements, path_index } = await generateMerkleProof(deposit)

  // Prepare circuit input
  const input = {
    // Public snark inputs
    // 公开的 snark 输入信息
    root: root,
    nullifierHash: deposit.nullifierHash,
    recipient: bigInt(recipient),
    relayer: 0,
    fee: 0,
    refund: 0,

    // Private snark inputs
    // 隐私的 snark 输入信息
    nullifier: deposit.nullifier,
    secret: deposit.secret,
    pathElements: path_elements,
    pathIndices: path_index,
  }

  console.log('Generating SNARK proof...')

  // =============================================
  // ================生成snark证明================
  //
  //
  const proofData = await websnarkUtils.genWitnessAndProve(groth16, input, circuit, proving_key)
  const { proof } = websnarkUtils.toSolidityInput(proofData)

  const args = [
    // root
    toHex(input.root),
    // 未花费的 nullifierHash
    toHex(input.nullifierHash),
    // 接收人地址
    toHex(input.recipient, 20),
    // 中继人地址
    toHex(input.relayer, 20),
    // 手续费
    toHex(input.fee),
    // 提款金额时转移的 ETH
    toHex(input.refund)
  ]

  return { proof, args }
}


/**
 * 关于 Tornado 的 抵押 和 提款
 *
 *  [抵押]
 *  - 生成一个随机的 secret 和一个 nullifier
 *  - 然后计算 secret和nullifier的Hash: pedersenHash(secret, nullifier) => commitment
 *  - 检查用户发送的ETH金额正确性
 *  - 将用户的 commitment 插入到 tree 中 (tree 是一颗 commitment 组成的 merkle树)
 *
 *
 *  [提款]
 *  - 用户证明他知道某些叶子的Merkle路径和该叶子的原像
 *  - 用户仅显示其承诺的无效符部分 (nullifier part of his commitment)，用于跟踪被使用过的 notes
 *  - 用户提供提款地址 <接收人>，并向提交提款交易的地址<中继人> 支付可选费用
 *  - 校验 SNARK proof
 *  - 检查是否未使用nullifier
 *  - 保存 nullifier (save nullifier)
 *  - 释放资金 (release funds)
 *
 * @returns {Promise<void>}
 */





// 最小示例
async function main() {
  web3 = new Web3(new Web3.providers.HttpProvider(RPC_URL, { timeout: 5 * 60 * 1000 }), null, { transactionConfirmationBlocks: 1 })
  circuit = require('./build/circuits/withdraw.json')

  // 获取证明 秘钥
  proving_key = fs.readFileSync('build/circuits/withdraw_proving_key.bin').buffer
  groth16 = await buildGroth16()
  netId = await web3.eth.net.getId()

  // 获取一个 ETH Tornado 合约实例
  contract = new web3.eth.Contract(require('./build/contracts/ETHTornado.json').abi, CONTRACT_ADDRESS)

  // 某个账户
  const account = web3.eth.accounts.privateKeyToAccount('0x' + PRIVATE_KEY)
  // 将账户 加到本地钱包中
  web3.eth.accounts.wallet.add('0x' + PRIVATE_KEY)
  // eslint-disable-next-line require-atomic-updates
  web3.eth.defaultAccount = account.address


  // 发起 质押, 生成一个 票据
  const note = await deposit()
  console.log('Deposited note:', note)

  // 根据 票据, 进行提款
  await withdraw(note, web3.eth.defaultAccount)
  console.log('Done')
  process.exit()
}

main()
