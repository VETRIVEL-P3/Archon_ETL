package com.p3solutions.archon_authentication_service.core.license_management;

import com.p3solutions.common_beans_dto.blob.BlobInfo;
import com.p3solutions.common_beans_dto.blob.abstract_blob.BlobAbstractService;
import com.p3solutions.utility.common_exceptions.ExceptionHandler;
import com.p3solutions.utility.license_management.validate.LicenseValidationChecker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.InputStream;

/**
 * Created by Suriyanarayanan K
 * on 16/02/21 11:48 AM.
 */
@Service
public class LicenseCheckerService {


    private static final String LICENSE_FILE="archon3license.lic";
    @Value(value="${archon.licensed}")
    private String licensedTo;
    String errorMessage;

    @Autowired
    private BlobAbstractService blobAbstractService;

    public Boolean archonLicenseCheck() {

        try {
            BlobInfo blobInfo=blobAbstractService.getFileFromDb(LICENSE_FILE);
            InputStream licFile=blobInfo.getInputStream();
            LicenseValidationChecker licenseValidationChecker=new LicenseValidationChecker(licFile , licensedTo);
            return licenseValidationChecker.validateArchonLicense();
        } catch (Exception e) {
            errorMessage="license validation failed due to exception";
            ExceptionHandler.exception(errorMessage , e);
            return false;
        }
    }

}
