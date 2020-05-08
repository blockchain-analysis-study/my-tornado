// https://tornado.cash
/*
* d888888P                                           dP              a88888b.                   dP
*    88                                              88             d8'   `88                   88
*    88    .d8888b. 88d888b. 88d888b. .d8888b. .d888b88 .d8888b.    88        .d8888b. .d8888b. 88d888b.
*    88    88'  `88 88'  `88 88'  `88 88'  `88 88'  `88 88'  `88    88        88'  `88 Y8ooooo. 88'  `88
*    88    88.  .88 88       88    88 88.  .88 88.  .88 88.  .88 dP Y8.   .88 88.  .88       88 88    88
*    dP    `88888P' dP       dP    dP `88888P8 `88888P8 `88888P' 88  Y88888P' `88888P8 `88888P' dP    dP
* ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
*/

pragma solidity 0.5.17;

import "./MerkleTreeWithHistory.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";


// 一个马甲合约
//
// 该合约 可能早就被 部署在链上了
// 通过 IVerifier v = IVerifier(address) 方式使用
contract IVerifier {
  function verifyProof(bytes memory _proof, uint256[6] memory _input) public returns(bool);
}

// ==================================================
// ==================== 超级重要 ====================
// 这个是 tornado 的核心合约 (龙卷风现金隐私解决方案)
// ==================================================
// ==================================================
contract Tornado is MerkleTreeWithHistory, ReentrancyGuard {

  // 定义 "面额值"
  uint256 public denomination;

  // 这个是存储 所有的 已花费的output的Hash
  mapping(bytes32 => bool) public nullifierHashes;

  // we store all commitments just to prevent accidental deposits with the same commitment
  //
  // 我们存储 所有承诺 只是为了防止相同承诺的意外(质押)存款
  mapping(bytes32 => bool) public commitments;

  // 一个外部的验证合约, 此处为马甲合约
  IVerifier public verifier;

  // operator can update snark verification key
  // after the final trusted setup ceremony operator rights are supposed to be transferred to zero address
  //
  // 操作人(operator) 可以更新 Snark验证密钥
  // 在最终的[受信任的设置 trusted setup]仪式上，应该将操作员权限转移到零地址
  address public operator;

  // 修饰器 只有 operator 才可以操作的限定
  modifier onlyOperator {
    require(msg.sender == operator, "Only operator can call this function.");
    _;
  }

  event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
  event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);

  /**
    @dev The constructor
    @param _verifier the address of SNARK verifier for this contract
    @param _denomination transfer amount for each deposit
    @param _merkleTreeHeight the height of deposits' Merkle Tree
    @param _operator operator address (see operator comment above)
  */
  //
  // 构造器
  //
  // _verifier: 该合同的SNARK验证者的地址
  // _denomination: 每次存款的转账金额 (规定了)
  // _merkleTreeHeight: 存款的默克尔树的高度
  // _operator: 操作人地址（请参阅上面的操作人评论）
  constructor(
    IVerifier _verifier,
    uint256 _denomination, // 每次质押时的都需要实例化 Tornado 合约,并且存入本次质押/提款的金额
    uint32 _merkleTreeHeight,
    address _operator
  )
  // 初始化 父合约的构造器  MerkleTreeWithHistory()
  MerkleTreeWithHistory(_merkleTreeHeight) public {
    require(_denomination > 0, "denomination should be greater than 0");
    verifier = _verifier;
    operator = _operator;
    denomination = _denomination;
  }

  /**
    @dev Deposit funds into the contract. The caller must send (for ETH) or approve (for ERC20) value equal to or `denomination` of this instance.
    @param _commitment the note commitment, which is PedersenHash(nullifier + secret)
  */
  // 发起质押 (token -> 加密币) AZTEC 中叫做 铸币 mint
  //
  // 将资金存入合同。 调用者必须发送 (对于ETH) 或批准 (对于ERC20) 等于该合约实例的 "面额" 的值。
  // _commitment: 一个票据承诺, 是 一个 PedersenHash(nullifier + secret)
  //
  function deposit(bytes32 _commitment) external payable nonReentrant {
    require(!commitments[_commitment], "The commitment has been submitted");

    // =======================================
    // =======================================
    // 将承诺 作为一个新的节点 插入 merkle tree
    // =======================================
    // =======================================
    uint32 insertedIndex = _insert(_commitment);
    commitments[_commitment] = true;

    // 然后再做 token 的转移
    _processDeposit();

    emit Deposit(_commitment, insertedIndex, block.timestamp);
  }

  /** @dev this function is defined in a child contract */
  function _processDeposit() internal;

  /**
    @dev Withdraw a deposit from the contract. `proof` is a zkSNARK proof data, and input is an array of circuit public inputs
    `input` array consists of:
      - merkle root of all deposits in the contract
      - hash of unique deposit nullifier to prevent double spends
      - the recipient of funds
      - optional fee that goes to the transaction sender (usually a relay)
  */
  // 从 contract 中提取 质押金。 proof是zkSNARK的证明数据，inputs 是电路公共 input的数组
  //      input的数组包括：
  //       - contract 中所有存款的merkle root
  //       - 唯一存款 nullifier的哈希值，以防止重复支出
  //       - 资金的接收者
  //       - 转到交易发送者（通常是中继人）的可选费用
  //
  //
  // _proof: snark的proof (外面自己生成)
  // _root: merkle root
  // _nullifierHash: 当前交易的 _nullifierHash
  // _recipient: 提取金额的接收人
  // _relayer: 中继人 (交易发送者)
  // _fee: 给中继人的 fee
  // _refund: 转移的 eth
  function withdraw(bytes calldata _proof, bytes32 _root, bytes32 _nullifierHash, address payable _recipient, address payable _relayer, uint256 _fee, uint256 _refund) external payable nonReentrant {

    // 费用不可以比 提取的金额大
    require(_fee <= denomination, "Fee exceeds transfer value");
    // 防止双花
    require(!nullifierHashes[_nullifierHash], "The note has been already spent");
    // 确保使用最新的
    require(isKnownRoot(_root), "Cannot find your merkle root"); // Make sure to use a recent one

    // 使用 证明合约 来校验证明
    require(verifier.verifyProof(_proof, [uint256(_root), uint256(_nullifierHash), uint256(_recipient), uint256(_relayer), _fee, _refund]), "Invalid withdraw proof");


    // 将本次 _nullifierHash 放入 nullifierHashes集中, 防止双花
    nullifierHashes[_nullifierHash] = true;

    // 然后做 token的转移
    _processWithdraw(_recipient, _relayer, _fee, _refund);
    emit Withdrawal(_recipient, _nullifierHash, _relayer, _fee);
  }

  /** @dev this function is defined in a child contract */
  function _processWithdraw(address payable _recipient, address payable _relayer, uint256 _fee, uint256 _refund) internal;

  /** @dev whether a note is already spent */
  /** note 是否已经用完 */
  function isSpent(bytes32 _nullifierHash) public view returns(bool) {
    return nullifierHashes[_nullifierHash];
  }

  /** @dev whether an array of notes is already spent */
  /** 是否已使用一系列 notes */
  function isSpentArray(bytes32[] calldata _nullifierHashes) external view returns(bool[] memory spent) {
    spent = new bool[](_nullifierHashes.length);
    for(uint i = 0; i < _nullifierHashes.length; i++) {
      if (isSpent(_nullifierHashes[i])) {
        spent[i] = true;
      }
    }
  }

  /**
    @dev allow operator to update SNARK verification keys. This is needed to update keys after the final trusted setup ceremony is held.
    After that operator rights are supposed to be transferred to zero address
  */
  // 允许 操作员 更新SNARK验证密钥。 举行最终的信任设置(trusted setup)仪式后，需要更新密钥
  // 之后，应该将操作员权限转移到零地址
  function updateVerifier(address _newVerifier) external onlyOperator {
    verifier = IVerifier(_newVerifier);
  }

  /** @dev operator can change his address */
  // 变更操作员的地址
  function changeOperator(address _newOperator) external onlyOperator {
    operator = _newOperator;
  }
}
