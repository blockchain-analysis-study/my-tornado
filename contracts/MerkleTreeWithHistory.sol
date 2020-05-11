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

// 注意, 这里定义一个库的 马甲
library Hasher {
  function MiMCSponge(uint256 in_xL, uint256 in_xR) public pure returns (uint256 xL, uint256 xR);
}

// Merkle树 合约
contract MerkleTreeWithHistory {

  // tree 上节点数据的大小限制
  uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

  // 代表 tree 上的 0值节点 (主要是为了 和非0的节点一起算 root Hash的)
  uint256 public constant ZERO_VALUE = 21663839004416932945382355908790599225266501822907911457504978515578255421292; // = keccak256("tornado") % FIELD_SIZE

  // 存放树支持的层数  (取值: 0 < x < 32)
  uint32 public levels;

  // the following variables are made public for easier testing and debugging and
  // are not supposed to be accessed in regular code
  //
  // 公开了以下变量，以简化测试和调试，并且不应在常规代码中访问

  // 被填充的 子树
  bytes32[] public filledSubtrees; // 做每一层计算时中转每一层上一次对应变动的 left 节点, 在这一层的 right 节点变动时会取出来一起算 rootHhash
  bytes32[] public zeros; // 这里面存放当全0值的tree 时, 每一层节点的值
  uint32 public currentRootIndex = 0; // 最近 100 笔插入merkle tree 时的root, 取值 (0 ~ 99)
  uint32 public nextIndex = 0;  // 下一个可被插入tree的 索引 (指的是, merkle tree 中最下面一层的 leaf 的索引, 取值: 0 ~ 2^30-1 )

  // 只保存最近 100 个历史的 root
  uint32 public constant ROOT_HISTORY_SIZE = 100;

  // root集, 只存最近 100 次插入的最终 merkle root
  // 用来做 root 校验用的
  bytes32[ROOT_HISTORY_SIZE] public roots;

  // 构造器
  constructor(uint32 _treeLevels) public {
    // 0 < levels < 32 , 即 merkletree 的深度不能为0且不得超过31
    //
    // tree 上可以存 2^30 == 1 073 741 824 (100 亿笔交易), 为什么是 2^30 而不是2^31 看下面 insert 中的图自己明白
    require(_treeLevels > 0, "_treeLevels should be greater than zero");
    require(_treeLevels < 32, "_treeLevels should be less than 32");

    // 初始化时 指定好当前 merkle tree 支持的层数
    levels = _treeLevels;

    bytes32 currentZero = bytes32(ZERO_VALUE);

    // 最开始的时候, merkle tree 只有一个 zero 节点
    zeros.push(currentZero);
    filledSubtrees.push(currentZero);

    // 使用 for 循环将整个 levels 深度的 tree 上的0值节点
    //
    //     假设一颗 全0值的 merkle tree  应该是下面这样的:
    //
    //                         r'' (hash(r', r'))
    //                       /   \
    //       (hash(0, 0))  r'      r'  (hash(0, 0))
    //                   /  \     /  \
    //                  0    0    0   0
    //
    // 由此可知, zeros 中保存的是每一层的 节点的值, 如: zeros[0] == 0, zeros[1] == r' zeros[2] == r''
    // 而, 子树也是一条线的形式, filledSubtrees中的值 类似 zeros 中的
    //
    // 下面的从 1 开始, 就是从 r' 这一层开始 算到 r''
    for (uint32 i = 1; i < levels; i++) {
      currentZero = hashLeftRight(currentZero, currentZero);
      zeros.push(currentZero);
      filledSubtrees.push(currentZero);
    }

    // 最开始的 root 只有 hash(0值, 0值)
    roots[0] = hashLeftRight(currentZero, currentZero);
  }

  /**
    @dev Hash 2 tree leaves, returns MiMC(_left, _right)
  */
  // 哈希2个left和right两个子节点，返回 MiMC（_left，_right）
  //
  // 这就是 Merkle tree 逐级往上求 hash 的方法
  function hashLeftRight(bytes32 _left, bytes32 _right) public pure returns (bytes32) {
    require(uint256(_left) < FIELD_SIZE, "_left should be inside the field");
    require(uint256(_right) < FIELD_SIZE, "_right should be inside the field");

    // R: 标识 merkle 的一个 root
    //
    // 先取 left 表示最开始的 root
    uint256 R = uint256(_left);
    uint256 C = 0; // 一个用于算Hash 的系数

    // 先叠加 左节点的hash
    (R, C) = Hasher.MiMCSponge(R, C);
    // 再叠加 右节点的hash
    R = addmod(R, uint256(_right), FIELD_SIZE);
    (R, C) = Hasher.MiMCSponge(R, C);

    // 返回 root Hash
    return bytes32(R);
  }


  // 插入一个叶子节点 (主要是插入 commitment)
  function _insert(bytes32 _leaf) internal returns(uint32 index) {
    uint32 currentIndex = nextIndex; // 获取当前可以被插入tree 的索引

    // 如果索引 等于 2^深度, 如: 2^31
    require(currentIndex != uint32(2)**levels, "Merkle tree is full. No more leafs can be added");

    // 先记录下一个可被插入的 索引
    nextIndex += 1;

    // 记录当前叶子结点
    bytes32 currentLevelHash = _leaf;

    // 左节点临时量
    bytes32 left;
    // 右节点临时量
    bytes32 right;

    // 根据层数来遍历
    for (uint32 i = 0; i < levels; i++) {

      // 注意, tree 节点的索引为,
      //
      //              r''                2^0     第2层
      //            /   \
      //         r'      r'              2^1     第1层
      //        /   \   /   \
      //       0     1 2      3          2^2     第0层   所以, 0 <= nextIndex < 2^2
      //
      //
      //
      // 最开始从叶子节点 0 索引开始放数据,一直放到3索引位置，则上面这颗tree只能容纳4个元素
      // 可知, index % 2 == 0 的位置为 左节点 (整除)
      //
      if (currentIndex % 2 == 0) {

        // 先将当前数据放置 左节点
        left = currentLevelHash;

        // 取出当前层的0值作为 右节点
        right = zeros[i];

        // 记录当前层最新的 左节点值, 在下次插入 右节点时要用
        filledSubtrees[i] = currentLevelHash;
      } else {

        // 取出上次 插入的 最新左节点值
        left = filledSubtrees[i];

        // 将数据放置 右节点
        right = currentLevelHash;
      }

      // 根据左右节点的值,求出当前 子树的 merkle root, 作为下一层放置
      currentLevelHash = hashLeftRight(left, right);

      currentIndex /= 2; // 决定下一次 for 是 先修改 上一层的 左节点 还是 右节点
    }

    // 计算出本次最新的root应该在最近100个root集合中放置的位置
    currentRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE; //  (0 ~ 99)

    // 最近100个root窗口集的对应位置放置当前root
    roots[currentRootIndex] = currentLevelHash;

    // 返回当前叶子结点插入索引, 即已经插入第几个叶子节点了
    return nextIndex - 1;
  }

  /**
    @dev Whether the root is present in the root history
  */
  // 根历史记录中是否存在根
  function isKnownRoot(bytes32 _root) public view returns(bool) {

    // 非0校验
    if (_root == 0) {
      return false;
    }

    // 从当前最新100次内的 最新 root 索引往前遍历,
    // 如果当前最新的root为最近的第51笔交易, 则 从51往0遍历
    uint32 i = currentRootIndex;
    do {
      if (_root == roots[i]) {
        return true;
      }

      // 这个就是为了后面 while 条件终止 而做的
      if (i == 0) {
        i = ROOT_HISTORY_SIZE;
      }
      i--;
    } while (i != currentRootIndex);

    return false;
  }

  /**
    @dev Returns the last root
  */
  // 返回最新的 交易插入 merkle tree 时，求到的 root
  function getLastRoot() public view returns(bytes32) {
    return roots[currentRootIndex];
  }
}
