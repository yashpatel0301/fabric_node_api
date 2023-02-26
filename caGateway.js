'use strict'
const FabricCAServices=require('fabric-ca-client')
const adminCreds=require("./connections/adminCreds.json")
const {buildCCPOrg, buildWallet, getMSPId}=require("./utils.js")

exports.buildCAClient = (orgId) => {
    const CCP = buildCCPOrg(orgId)
	const CA_INFO = CCP.certificateAuthorities[`ca.${orgId.toLowerCase()}.example.com`];
	const CA_TLS_CACerts = CA_INFO.tlsCACerts.pem;
	const CA_CLIENT = new FabricCAServices(CA_INFO.url, { trustedRoots: CA_TLS_CACerts, verify: false }, CA_INFO.caName);

	console.log(`Built a CA Client named ${CA_INFO.caName}`);
	return CA_CLIENT;
};

exports.enrollAdmin=async function(orgId){
    try {
		// Building a CA Client
        const CA_CLIENT = module.exports.buildCAClient(orgId)
        
		// Retirving the wallet object
        const wallet = await buildWallet()
        const orgMspId = getMSPId(orgId)


		// Check to see if we've already enrolled the admin user.
		const identity = await wallet.get(adminCreds.userId);
		if (identity) {
			console.log('An identity for the admin user already exists in the wallet');
			return;
		}

		// Enroll the admin user, and import the new identity into the wallet.
		const enrollment = await CA_CLIENT.enroll({ enrollmentID: adminCreds.userId, enrollmentSecret: adminCreds.password });
		const x509Identity = {
			credentials: {
				certificate: enrollment.certificate,
				privateKey: enrollment.key.toBytes(),
			},
			mspId: orgMspId,
			type: 'X.509',
		};
    

		// Stroing the identity in the wallet
		await wallet.put(adminCreds.userId, x509Identity);
		console.log('Successfully enrolled admin user and imported it into the wallet');
	} catch (error) {
		console.error(`Failed to enroll admin user : ${error}`);
	}
}

exports.registerAndEnrollUser = async (orgId, userId, role) => {
	try {
        const CA_CLIENT = module.exports.buildCAClient(orgId)

        const wallet = await buildWallet()
        const orgMspId = getMSPId(orgId)
        
		const userIdentity = await wallet.get(userId);
		if (userIdentity) {
			console.log(`An identity for the user ${userId} already exists in the wallet`);
			return;
		}

		const adminIdentity = await wallet.get(adminCreds.userId);
		if (!adminIdentity) {
			console.log('An identity for the admin user does not exist in the wallet');
			console.log('Enroll the admin user before retrying');
			return;
		}

		const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
		const adminUser = await provider.getUserContext(adminIdentity, adminCreds.userId);

		const secret = await CA_CLIENT.register({
			affiliation: `${orgId.toLowerCase()}.department1`,
			enrollmentID: userId,
			role: role
		}, adminUser);

		const enrollment = await CA_CLIENT.enroll({
			enrollmentID: userId,
			enrollmentSecret: secret
		});

		const x509Identity = {
			credentials: {
				certificate: enrollment.certificate,
				privateKey: enrollment.key.toBytes(),
			},
			mspId: orgMspId,
			type: 'X.509',
		};


		// Stroing the identity in the wallet
		await wallet.put(userId, x509Identity);

		return x509Identity;
	} catch (error) {
		console.error(`Failed to register user : ${error}`);
		return error
	}
};

exports.getIdentity=async function(identityName){
    try{
		const wallet = await buildWallet()
		const identity = await wallet.get(identityName)
		return identity
	}catch(err){
		return err
	}

}

module.exports.registerAndEnrollUser('org1', 'user2', 'client').then(console.log)