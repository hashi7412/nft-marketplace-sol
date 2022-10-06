use crate::constants::*;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{clock, program_option::COption};
use anchor_spl::token::{self, TokenAccount, Token, Mint};
use std::convert::Into;
use std::convert::TryInto;

declare_id!("E1t7mAFARVZG8DoozV38Vyt4jJjcS9GnmWCAtSa8sicq");
mod constants {
    pub const LP_TOKEN_MINT_PUBKEY: &str = "D9DaGmpuzqzYnr4qxXP7EZCu9h1RE47eu3XnayB1e9oZ";
    pub const LP_DEPOSIT_REQUIREMENT: u64 = 10_000_000_000;
    pub const STAKING_TOTAL_REWARD: u64 = 1_000_000_000_000;
    pub const MIN_DURATION: u64 = 1;
}

const PRECISION: u128 = u64::MAX as u128;

pub fn update_rewards(
    pool: &mut Account<Pool>,
    user: Option<&mut Box<Account<User>>>,
    total_staked: u64,
) -> Result<()> {
    let clock = clock::Clock::get().unwrap();
    let mut last_time_reward_applicable =
        get_last_time_reward_applicable(pool.reward_duration_end, clock.unix_timestamp);

    if last_time_reward_applicable == pool.last_update_time {
        pool.reward_duration_end = pool.last_update_time.checked_add(pool.reward_duration).unwrap();
        last_time_reward_applicable =
            get_last_time_reward_applicable(pool.reward_duration_end, clock.unix_timestamp);
    }

    if pool.last_update_time > last_time_reward_applicable {
        pool.last_update_time = last_time_reward_applicable;
    }

    pool.reward_rate = constants::STAKING_TOTAL_REWARD.checked_div(30 * 24 * 60 * 60).unwrap();

    msg!("pool.reward_per_token_stored: {:?}", pool.reward_per_token_stored);
    pool.reward_per_token_stored = reward_per_token(
        total_staked,
        pool.reward_per_token_stored,
        last_time_reward_applicable,
        pool.last_update_time,
        pool.reward_rate,
    );

    pool.last_update_time = last_time_reward_applicable;

    if let Some(u) = user {
        u.reward_per_token_pending = earned(
            u.balance_staked,
            pool.reward_per_token_stored,
            u.reward_per_token_complete,
            u.reward_per_token_pending,
        );
        msg!("u.reward_per_token_pending: {:?}", u.reward_per_token_pending);
        u.reward_per_token_complete = pool.reward_per_token_stored;
    }
    
    Ok(())
}

pub fn get_last_time_reward_applicable(reward_duration_end: u64, unix_timestamp: i64) -> u64 {
    return std::cmp::min(unix_timestamp.try_into().unwrap(), reward_duration_end);
}

pub fn reward_per_token(
    total_staked: u64,
    reward_per_token_stored: u128,
    last_time_reward_applicable: u64,
    last_update_time: u64,
    reward_rate: u64,
) -> u128 {
    if total_staked == 0 {
        return reward_per_token_stored;
    }

    return reward_per_token_stored
                .checked_add(
                    ((last_time_reward_applicable as u128)
                                        .checked_sub(last_update_time as u128)
                                        .unwrap())
                    .checked_mul(reward_rate as u128)
                    .unwrap()
                    .checked_mul(PRECISION)
                    .unwrap()
                    .checked_div(total_staked as u128)
                    .unwrap()
                )
                .unwrap();
}

pub fn earned(
    balance_staked: u64,
    reward_per_token_x: u128,
    user_reward_per_token_x_paid: u128,
    user_reward_x_pending: u64,
) -> u64 {
    return (balance_staked as u128)
        .checked_mul(
            (reward_per_token_x as u128)
                .checked_sub(user_reward_per_token_x_paid as u128)
                .unwrap(),
        )
        .unwrap()
        .checked_div(PRECISION)
        .unwrap()
        .checked_add(user_reward_x_pending as u128)
        .unwrap()
        .try_into() 
        .unwrap()
}

#[program]
pub mod nft_staking {
    use super::*;

    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        pool_nonce: u8,
        vault_nonce: u8,
        reward_duration: u64,
    ) -> Result<()> {
        if reward_duration < MIN_DURATION {
            return Err(ErrorCode::DurationTooShort.into());
        }

        // lp lockup
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.lp_token_depositor.to_account_info(),
                to: ctx.accounts.lp_token_pool_vault.to_account_info(),
                authority: ctx.accounts.lp_token_deposit_authority.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, constants::LP_DEPOSIT_REQUIREMENT)?;

        let pool = &mut ctx.accounts.pool;

        pool.authority = ctx.accounts.authority.key();
        pool.nonce = pool_nonce;
        pool.paused = false;
        pool.lp_token_pool_vault = ctx.accounts.lp_token_pool_vault.key();
        pool.reward_mint = ctx.accounts.reward_mint.key();
        pool.reward_vault = ctx.accounts.reward_vault.key();
        pool.reward_duration = reward_duration;

        let current_time = clock::Clock::get().unwrap().unix_timestamp.try_into().unwrap();

        pool.last_update_time = current_time;
        pool.reward_duration_end = current_time.checked_add(pool.reward_duration).unwrap();
        pool.reward_rate = constants::STAKING_TOTAL_REWARD.checked_div(pool.reward_duration).unwrap();

        pool.reward_per_token_stored = 0;
        pool.user_stake_count = 0;

        let vault = &mut ctx.accounts.vault;
        vault.nonce = vault_nonce;
        vault.nfts = vec![];
        
        Ok(())
    }

    pub fn create_user(ctx: Context<CreateUser>, nonce: u8) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.nft_mints = vec![];
        user.pool = *ctx.accounts.pool.to_account_info().key;
        user.owner = *ctx.accounts.owner.key;
        user.reward_per_token_complete = 0;
        user.reward_per_token_pending = 0;
        user.balance_staked = 0;
        user.nonce = nonce;

        let pool = &mut ctx.accounts.pool;
        pool.user_stake_count = pool.user_stake_count.checked_add(1).unwrap();

        Ok(())
    }

    pub fn pause(ctx: Context<Pause>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.paused = true;

        //lp refund
        let seeds = &[
            pool.to_account_info().key.as_ref(),
            &[pool.nonce],
        ];
        let pool_signer = &[&seeds[..]];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.lp_token_pool_vault.to_account_info(),
                to: ctx.accounts.lp_token_receiver.to_account_info(),
                authority: ctx.accounts.pool_signer.to_account_info(),
            },
            pool_signer,
        );

        token::transfer(cpi_ctx, ctx.accounts.lp_token_pool_vault.amount)?;
        
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::CloseAccount {
                account: ctx.accounts.lp_token_pool_vault.to_account_info(),
                destination: ctx.accounts.authority.to_account_info(),
                authority: ctx.accounts.pool_signer.to_account_info(),
            },
            pool_signer,
        );
        token::close_account(cpi_ctx)?;
        
        pool.lp_token_pool_vault = Pubkey::default();

        Ok(())
    }

    pub fn unpause(ctx: Context<Unpause>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.paused = false;

        //the prior token vault was closed when pausing
        pool.lp_token_pool_vault = ctx.accounts.lp_token_pool_vault.key();

        //lp lockup
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.lp_token_depositor.to_account_info(),
                to: ctx.accounts.lp_token_pool_vault.to_account_info(),
                authority: ctx.accounts.lp_token_deposit_authority.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, 10_000_000_000_000)?;
        
        Ok(())
    }

    pub fn stake(ctx: Context<Stake>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        if pool.paused {
            return Err(ErrorCode::PoolPaused.into());
        }

        let vault = &mut ctx.accounts.vault;
        let total_staked = vault.nfts.len();
        let user = &mut ctx.accounts.user;
        update_rewards(
            pool,
            Some(user),
            total_staked as u64,
        )
        .unwrap();
        
        user.balance_staked = user.balance_staked.checked_add(1 as u64).unwrap();

        // Transfer tokens into the stake vault.
        {
            let cpi_ctx = CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.stake_from_account.to_account_info(),
                    to: ctx.accounts.stake_to_account.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(), //todo use user account as signer
                },
            );
            token::transfer(cpi_ctx, 1 as u64)?;

            ctx.accounts.vault.nfts.push(ctx.accounts.stake_to_account.key());
            
            user.nft_mints.push(ctx.accounts.stake_to_account.mint)
        }

        Ok(())
    }

    pub fn unstake(ctx: Context<Stake>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user;
        let vault = &mut ctx.accounts.vault;
        
        let total_staked = vault.nfts.len();
        update_rewards(
            pool,
            Some(user),
            total_staked as u64,
        )
        .unwrap();
        user.balance_staked = user.balance_staked.checked_sub(1 as u64).unwrap();

        // Transfer tokens from the pool vault to user vault.
        {
            let seeds = &[
                pool.to_account_info().key.as_ref(),
                &[pool.nonce],
            ];
            let pool_signer = &[&seeds[..]];

            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.stake_to_account.to_account_info(),
                    to: ctx.accounts.stake_from_account.to_account_info(),
                    authority: ctx.accounts.pool_signer.to_account_info(),
                },
                pool_signer,
            );
            token::transfer(cpi_ctx, 1 as u64)?;

            let stake_to_account_key = ctx.accounts.stake_to_account.key();
            let stake_to_account_mint = ctx.accounts.stake_to_account.mint;

            let index = vault.nfts.iter().position(|x| *x == stake_to_account_key).unwrap();
            vault.nfts.remove(index);

            let index = user.nft_mints.iter().position(|x| *x == stake_to_account_mint).unwrap();
            user.nft_mints.remove(index);
        }

        Ok(())
    }

    pub fn claim(ctx: Context<ClaimReward>) -> Result<()> {
        let total_staked = ctx.accounts.vault.nfts.len();
        let user_opt = Some(&mut ctx.accounts.user);
        update_rewards(
            &mut ctx.accounts.pool,
            user_opt,
            total_staked as u64,
        )
        .unwrap();

        let seeds = &[
            ctx.accounts.pool.to_account_info().key.as_ref(),
            &[ctx.accounts.pool.nonce],
        ];
        let pool_signer = &[&seeds[..]];

        if ctx.accounts.user.reward_per_token_pending > 0 {
            let mut reward_amount = ctx.accounts.user.reward_per_token_pending;
            let vault_balance = ctx.accounts.reward_vault.amount;

            ctx.accounts.user.reward_per_token_pending = 0;
            if vault_balance < reward_amount {
                reward_amount = vault_balance;
            }

            if reward_amount > 0 {
                let cpi_ctx = CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.reward_vault.to_account_info(),
                        to: ctx.accounts.reward_account.to_account_info(),
                        authority: ctx.accounts.pool_signer.to_account_info(),
                    },
                    pool_signer,
                );
                token::transfer(cpi_ctx, reward_amount)?;
            }
        }

        Ok(())
    }

    pub fn close_user(ctx: Context<CloseUser>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.user_stake_count = pool.user_stake_count.checked_sub(1).unwrap();
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(pool_nonce: u8, vault_nonce: u8)]
pub struct InitializePool<'info> {
    authority: UncheckedAccount<'info>,

    #[account(
        mut,
        // constraint = lp_token_pool_vault.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap(),
        constraint = lp_token_pool_vault.owner == pool_signer.key(),
    )]
    lp_token_pool_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        // constraint = lp_token_depositor.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap()
    )]
    lp_token_depositor: Box<Account<'info, TokenAccount>>,
    lp_token_deposit_authority: Signer<'info>,

    reward_mint: Box<Account<'info, Mint>>,
    #[account(
        constraint = reward_vault.mint == reward_mint.key(),
        constraint = reward_vault.owner == pool_signer.key(),
        constraint = reward_vault.close_authority == COption::None,
    )]
    reward_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool_nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    #[account(
        zero,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        init,
        payer = owner,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref()
        ],
        bump = vault_nonce,
        space = 10240,
    )]
    vault: Box<Account<'info, Vault>>,
    owner: Signer<'info>,
    
    token_program: Program<'info, Token>,
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nonce: u8)]
pub struct CreateUser<'info> {
    // Stake instance.
    #[account(
        mut,
        constraint = !pool.paused,
    )]
    pool: Box<Account<'info, Pool>>,
    // Member.
    #[account(
        init,
        payer = owner,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref()
        ],
        bump = nonce,
        space = 10240, //// need to calculate space 
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    // Misc.
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(mut)]
    lp_token_pool_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    lp_token_receiver: Box<Account<'info, TokenAccount>>,

    #[account(
        mut, 
        has_one = authority,
        has_one = lp_token_pool_vault,
        constraint = !pool.paused,
    )]
    pool: Box<Account<'info, Pool>>,
    authority: Signer<'info>,

    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Unpause<'info> {
    #[account(
        mut,
        constraint = lp_token_pool_vault.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap(),
        constraint = lp_token_pool_vault.owner == pool_signer.key(),
    )]
    // #[account(
    //     mut,
    //     constraint = lp_token_pool_vault.owner == pool_signer.key(),
    // )]
    lp_token_pool_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        constraint = lp_token_depositor.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap()
    )]
    // #[account(
    //     mut,
    // )]
    lp_token_depositor: Box<Account<'info, TokenAccount>>,
    lp_token_deposit_authority: Signer<'info>,

    #[account(
        mut, 
        has_one = authority,
        constraint = pool.paused,
    )]
    pool: Box<Account<'info, Pool>>,
    authority: Signer<'info>,

    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    // Global accounts for the staking instance.
    #[account(
        mut,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut,
    )]
    vault: Box<Account<'info, Vault>>,
    #[account(
        mut,
        constraint = stake_to_account.owner == *pool_signer.key,
    )]
    stake_to_account: Box<Account<'info, TokenAccount>>,

    // User.
    #[account(
        mut, 
        has_one = owner, 
        has_one = pool,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref()
        ],
        bump = user.nonce,
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    #[account(mut)]
    stake_from_account: Box<Account<'info, TokenAccount>>,

    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    // Misc.
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClaimReward<'info> {
    // Global accounts for the staking instance.
    #[account(
        mut, 
        has_one = reward_vault,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut, 
    )]
    vault: Box<Account<'info, Vault>>,
    #[account(mut)]
    reward_vault: Box<Account<'info, TokenAccount>>,

    // User.
    #[account(
        mut,
        has_one = owner,
        has_one = pool,
        seeds = [
            owner.to_account_info().key.as_ref(),
            pool.to_account_info().key.as_ref()
        ],
        bump = user.nonce,
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    #[account(mut)]
    reward_account: Box<Account<'info, TokenAccount>>,

    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    // Misc.
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CloseUser<'info> {
    #[account(
        mut, 
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut,
        close = owner,
        has_one = owner,
        has_one = pool,
        seeds = [
            owner.to_account_info().key.as_ref(),
            pool.to_account_info().key.as_ref()
        ],
        bump = user.nonce,
        constraint = user.balance_staked == 0,
        constraint = user.reward_per_token_pending == 0,
    )]
    user: Account<'info, User>,
    owner: Signer<'info>,
}

#[account]
pub struct Pool {
    /// Priviledged account.
    pub authority: Pubkey,
    /// Nonce to derive the program-derived address owning the vaults.
    pub nonce: u8,
    /// Paused state of the program
    pub paused: bool,
    /// The vault holding users' lp
    pub lp_token_pool_vault: Pubkey,
    /// Mint of the reward token.
    pub reward_mint: Pubkey,
    /// Vault to store reward tokens.
    pub reward_vault: Pubkey,
    /// The period which rewards are linearly distributed.
    pub reward_duration: u64,
    /// The timestamp at which the current reward period ends.
    pub reward_duration_end: u64,
    /// The last time reward states were updated.
    pub last_update_time: u64,
    /// Rate of reward distribution.
    pub reward_rate: u64,
    /// Last calculated reward per pool token.
    pub reward_per_token_stored: u128,
    /// Users staked
    pub user_stake_count: u32,
}

#[account]
pub struct Vault {
    /// NFT accounts staked
    pub nfts: Vec<Pubkey>,
    pub nonce: u8,
}

#[account]
#[derive(Default)]
pub struct User {
    /// Pool the this user belongs to.
    pub pool: Pubkey,
    /// The owner of this account.
    pub owner: Pubkey,
    /// The amount of token claimed.
    pub reward_per_token_complete: u128,
    /// The amount of token pending claim.
    pub reward_per_token_pending: u64,
    /// The amount staked.
    pub balance_staked: u64,
    /// Signer nonce.
    pub nonce: u8,
    /// NFT mints stacked
    pub nft_mints: Vec<Pubkey>,
}

#[error]
pub enum ErrorCode {
    #[msg("Insufficient funds to unstake.")]
    InsufficientFundUnstake,
    #[msg("Amount must be greater than zero.")]
    AmountMustBeGreaterThanZero,
    #[msg("Reward B cannot be funded - pool is single stake.")]
    SingleStakeTokenBCannotBeFunded,
    #[msg("Pool is paused.")]
    PoolPaused,
    #[msg("Duration cannot be shorter than one day.")]
    DurationTooShort,
}
