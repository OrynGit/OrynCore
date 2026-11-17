//! Oryn 执行配额钩子（原实现无此文件）。仅在当前运行线程设置，不跨请求保留预算。
use std::boxed::Box;
use std::{cell::RefCell,time::{Duration,Instant}};
#[derive(Clone)]struct Budget{steps:usize,bytes:usize,depth:usize,end:Instant}
std::thread_local!{static BUDGET:RefCell<Option<Budget>>=const{RefCell::new(None)};}
/// 超过预算使用不可被 jq try/catch 捕获的 unwind；宿主必须用 catch_unwind 包裹一次完整执行。
#[derive(Debug)]pub struct Exhausted;
/// 启用当前线程配额。
pub fn start(){BUDGET.with(|b|*b.borrow_mut()=Some(Budget{steps:200_000,bytes:8*1024*1024,depth:0,end:Instant::now()+Duration::from_millis(100)}));}
/// 清除配额。
pub fn clear(){BUDGET.with(|b|*b.borrow_mut()=None);}
/// 每个解释步骤及 iterator 输出检查时间和累计值体积。
pub fn charge(bytes:usize){let exceeded=BUDGET.with(|b|{let mut b=b.borrow_mut();let Some(v)=b.as_mut()else{return false};if v.steps==0||bytes>v.bytes||Instant::now()>=v.end{return true}v.steps-=1;v.bytes-=bytes;false});if exceeded{std::panic::resume_unwind(Box::new(Exhausted));}}
/// 一次同步求值调用的栈深度守卫。
pub struct Depth;
/// 进入解释器同步调用。
pub fn enter()->Depth{charge(0);let exceeded=BUDGET.with(|b|{if let Some(v)=b.borrow_mut().as_mut(){v.depth+=1;v.depth>128}else{false}});if exceeded{std::panic::resume_unwind(Box::new(Exhausted));}Depth}
impl Drop for Depth{fn drop(&mut self){BUDGET.with(|b|{if let Some(v)=b.borrow_mut().as_mut(){v.depth=v.depth.saturating_sub(1)}});}}
