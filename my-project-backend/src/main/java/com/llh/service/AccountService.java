package com.llh.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.llh.entity.dto.Account;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AccountService extends IService<Account>, UserDetailsService {
    Account findAccountByNameOrEmail(String test);
}
