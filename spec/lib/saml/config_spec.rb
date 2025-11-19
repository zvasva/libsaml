require 'spec_helper'

describe Saml::Config do

  let(:private_key_file) {File.join('spec', 'fixtures', 'key.pem')}
  let(:private_key) {OpenSSL::PKey::RSA.new(File.read(private_key_file))}

  let(:certificate_file) {File.join('spec', 'fixtures', 'certificate.pem')}
  let(:certificate) {OpenSSL::X509::Certificate.new(File.read(certificate_file))}

  let(:certificate_chain_file) {File.join('spec', 'fixtures', 'certificate_chain.pem')}

  after do
    Saml::Config.ssl_private_key = nil
    Saml::Config.ssl_certificate = nil
    Saml::Config.ssl_certificate_chain = nil
  end


  describe '#signature_method' do
    it 'returns the default signature algorithm' do
      expect(Saml::Config.signature_algorithm).to eq "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    end
  end

  describe '#digest_method' do
    it 'returns the default digest method algorithm' do
      expect(Saml::Config.digest_algorithm).to eq "http://www.w3.org/2001/04/xmlenc#sha256"
    end
  end

  describe '#ssl_private_key_file' do
    it 'initializes an OpenSSL::PKey::RSA' do
      expect(OpenSSL::PKey::RSA).to receive(:new).with File.read(private_key_file)
      Saml::Config.ssl_private_key_file = private_key_file
    end

    it 'sets #ssl_private_key' do
      allow(OpenSSL::PKey::RSA).to receive(:new).and_return 'key'
      Saml::Config.ssl_private_key_file = private_key_file
      expect(Saml::Config.ssl_private_key).to eq 'key'
    end
  end

  describe '#ssl_private_key' do
    it 'sets #ssl_private_key' do
      Saml::Config.ssl_private_key = private_key
      expect(Saml::Config.ssl_private_key).to eq private_key
    end
  end

  describe '#ssl_certificate_file' do
    context 'with a single certificate' do
      it 'sets #ssl_certificate' do
        Saml::Config.ssl_certificate_file = certificate_file
        expect(Saml::Config.ssl_certificate).to be_a(OpenSSL::X509::Certificate)
      end

      it 'sets #ssl_certificate_chain to nil' do
        Saml::Config.ssl_certificate_file = certificate_file
        expect(Saml::Config.ssl_certificate_chain).to be_nil
      end
    end

    context 'with a certificate bundle (cert + chain)' do
      it 'sets #ssl_certificate to the first certificate' do
        Saml::Config.ssl_certificate_file = certificate_chain_file
        expect(Saml::Config.ssl_certificate).to be_a(OpenSSL::X509::Certificate)
        expect(Saml::Config.ssl_certificate.subject.to_s).to include('ClientCert')
      end

      it 'sets #ssl_certificate_chain to remaining certificates' do
        Saml::Config.ssl_certificate_file = certificate_chain_file
        expect(Saml::Config.ssl_certificate_chain).to be_an(Array)
        expect(Saml::Config.ssl_certificate_chain.length).to eq 1
        expect(Saml::Config.ssl_certificate_chain.first).to be_a(OpenSSL::X509::Certificate)
        expect(Saml::Config.ssl_certificate_chain.first.subject.to_s).to include('IntermediateCert')
      end
    end

    context 'with nil or empty' do
      it 'sets both to nil when given nil' do
        Saml::Config.ssl_certificate_file = nil
        expect(Saml::Config.ssl_certificate).to be_nil
        expect(Saml::Config.ssl_certificate_chain).to be_nil

        Saml::Config.ssl_certificate_file = ''
        expect(Saml::Config.ssl_certificate).to be_nil
        expect(Saml::Config.ssl_certificate_chain).to be_nil
      end
    end
  end

  describe '#ssl_certificate' do
    it 'sets #ssl_certificate' do
      Saml::Config.ssl_certificate = certificate
      expect(Saml::Config.ssl_certificate).to eq certificate
    end
  end

  describe '#ssl_certificate_chain' do
    it 'sets #ssl_certificate_chain' do
      chain = [certificate, certificate]
      Saml::Config.ssl_certificate_chain = chain
      expect(Saml::Config.ssl_certificate_chain).to eq chain
    end
  end

  describe '#include_nested_prefixlist' do
    it 'is disabled by default' do
      expect(Saml::Config.include_nested_prefixlist).to eq false
    end
  end
end
