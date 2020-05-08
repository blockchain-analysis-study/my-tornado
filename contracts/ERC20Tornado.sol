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

import "./Tornado.sol";


// 这是一个 ERC20 合约的再外一层封装的合约
contract ERC20Tornado is Tornado {

  // 某个 ERC20 token 合约地址
  address public token;

  constructor(
    IVerifier _verifier,
    uint256 _denomination,
    uint32 _merkleTreeHeight,
    address _operator,
    address _token
  ) Tornado(_verifier, _denomination, _merkleTreeHeight, _operator) public {
    token = _token;
  }

  // 开始发起 质押
  function _processDeposit() internal {

    // 转 ERC20 时, 不允许转 ETH
    require(msg.value == 0, "ETH value is supposed to be 0 for ERC20 instance");

    // msg.sender 转 denomination 金额 ERC20 token 给当前合约
    //
    // 当前合约使用 token 合约将 msg.sender 的 denomination 个token 转给 当前合约
    _safeErc20TransferFrom(msg.sender, address(this), denomination);
  }



  // 开始发起 取款
  //
  // _recipient: 取款接受者
  // _relayer: 中继器 (一般使用当前 msg.sender ??)
  // _fee: 手续
  // _refund: 需要由 当前msg.sender 转移的 eth
  function _processWithdraw(address payable _recipient, address payable _relayer, uint256 _fee, uint256 _refund) internal {

    // 使用 value 作为提款金额 ??
    require(msg.value == _refund, "Incorrect refund amount received by the contract"); // 合同收到的退款金额不正确


    // 当前合约 转 token合约的 (denomination - _fee)个token 给 _recipient
    _safeErc20Transfer(_recipient, denomination - _fee);

    // 将手续费 转给 _relayer
    if (_fee > 0) {
      _safeErc20Transfer(_relayer, _fee);
    }

    // 转移eth
    if (_refund > 0) {
      (bool success, ) = _recipient.call.value(_refund)("");
      if (!success) {
        // let's return _refund back to the relayer
        //
        // 让我们将_退款退还给中继员 ?? 这么说, 中继员一般指 本笔交易的 msg.sender
        _relayer.transfer(_refund);
      }
    }
  }

  // 指, 当前 msg.sender 账户, 帮 from 从from 的钱包中花 amount 金额给 to
  function _safeErc20TransferFrom(address _from, address _to, uint256 _amount) internal {

    // 跨合约调用 该 ERC20 token 合约的 transferFrom()
    // 当前 msg.sender 出 gas, 代理提 from 账户转 amount 给to,
    // 其实 ERC20 是 from 出的, 而 msg.sender 只是出了 gas
    //
    // 对于 token 合约来说 msg.sender 就是当前合约
    // 将 from 的 amount  转给 to
    (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd /* transferFrom */, _from, _to, _amount));
    require(success, "not enough allowed tokens");

    // if contract returns some data lets make sure that is `true` according to standard
    //
    // 如果 token 合约的跨合约调用 返回了一些数据，请确保根据标准，该数据为“ true”
    if (data.length > 0) {
      require(data.length == 32, "data length should be either 0 or 32 bytes");
      success = abi.decode(data, (bool));
      require(success, "not enough allowed tokens. Token returns false.");
    }
  }


  // 转账
  function _safeErc20Transfer(address _to, uint256 _amount) internal {

    // 发起 跨合约转账调用 token 合约的 transfer() 函数
    // 当前合约赚钱给
    (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb /* transfer */, _to, _amount));
    require(success, "not enough tokens");

    // if contract returns some data lets make sure that is `true` according to standard
    if (data.length > 0) {
      require(data.length == 32, "data length should be either 0 or 32 bytes");
      success = abi.decode(data, (bool));
      require(success, "not enough tokens. Token returns false.");
    }
  }
}
