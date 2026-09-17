use crate::commitment::CommitGroup;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("too many messages: got {got}, max is {max}")]
    TooManyMessages { got: usize, max: usize },
    #[error("message vector must not be empty")]
    EmptyMessages,
    #[error("signature is not a valid curve point")]
    InvalidSignature,
    #[error("revealed index {idx} is out of bounds for message set of length {len}")]
    InvalidRevealIndex { idx: usize, len: usize },
    #[error("commitment is in wrong group, expected group {exp_group}")]
    CommitmentWrongGroup { exp_group: CommitGroup },
    #[error("blind sign commitment check failed")]
    InvalidCommitmentOpeningBlindSign,
    #[error("multi-scalar multiplication failed")]
    MsmFailed,
    #[error("scalar is zero and has no inverse")]
    ZeroScalar,
    #[error("cannot aggregate an empty set of partial signatures")]
    EmptyPartialSignatures,
    #[error("partial signature index {index} is invalid")]
    InvalidShareIndex { index: usize },
    #[error("partial signature index {index} is duplicated")]
    DuplicateShareIndex { index: usize },
}
