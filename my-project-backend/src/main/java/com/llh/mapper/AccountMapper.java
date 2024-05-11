package com.llh.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.llh.entity.dto.Account;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AccountMapper extends BaseMapper<Account> {

}
