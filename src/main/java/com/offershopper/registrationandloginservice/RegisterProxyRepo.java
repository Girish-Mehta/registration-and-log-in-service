package com.offershopper.registrationandloginservice;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface RegisterProxyRepo extends MongoRepository<RegisterInfo, String>{

}
