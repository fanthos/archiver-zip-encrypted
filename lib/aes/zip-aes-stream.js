'use strict';

const inherits = require('util').inherits;
const AesHmacEtmStream = require('./aes-hmac-etm-stream');
const ZipStream = require('zip-stream');
const {DeflateCRC32Stream, CRC32Stream} = require('crc32-stream');
const crc32 = require('buffer-crc32');
const {ZipArchiveOutputStream, ZipArchiveEntry} = require('compress-commons');

const ZIP_AES_METHOD = 99;

/**
 * Overrides ZipStream with AES-256 encryption
 */
const ZipAesStream = function (options = {zlib: {}}) {
    if (!(this instanceof ZipAesStream)) {
        return new ZipAesStream(options);
    }

    this.key = options.password;
    if (!this.key) {
        this.key = false;
    } else if (!Buffer.isBuffer(this.key)) {
        this.key = Buffer.from(this.key);
    }

    ZipStream.call(this, options);
};
inherits(ZipAesStream, ZipStream);

function _buildAesExtraField(ae) {
    let buffer = Buffer.alloc(11);
    buffer.writeUInt16LE(0x9901, 0); // AES header ID
    buffer.writeUInt16LE(0x7, 2); // data size, hardcoded
    buffer.writeUInt16LE(0x1, 4); // AE-1, i.e. CRC is present
    buffer.writeUInt16LE(0x4541, 6); // vendor id, hardcoded
    buffer.writeInt8(0x3, 8); // encryption strength: AES-256
    buffer.writeUInt16LE(ae.getMethod(), 9); // actual compression method

    return buffer;
}

ZipAesStream.prototype._writeLocalFileHeader = function (ae) {
    if (!ae.encryptKey) {
        return ZipStream.prototype._writeLocalFileHeader.call(this, ae);
    }
    let gpb = ae.getGeneralPurposeBit();

    // set AES-specific fields
    gpb.useEncryption(true);
    ae.setExtra(_buildAesExtraField(ae));
    ae.setMethod(ZIP_AES_METHOD);
    ae.setVersionNeededToExtract(51);

    ZipStream.prototype._writeLocalFileHeader.call(this, ae);
};

ZipAesStream.prototype._appendBuffer = function(ae, source, callback) {
    if (!ae.encryptKey) {
        return ZipStream.prototype._appendBuffer.call(this, ae, source, callback);
    }
    ae.setSize(source.length);
    ae.setCompressedSize(source.length + 28);
    ae.setCrc(crc32.unsigned(source));

    this._writeLocalFileHeader(ae);

    this._smartStream(ae, callback).end(source);
};

/**
 * Pass stream from compressor through encryption stream
 */
ZipAesStream.prototype._smartStream = function (ae, callback) {
    if (!ae.encryptKey) {
        return ZipStream.prototype._smartStream.call(this, ae, callback);
    }
    var deflate = ae.getExtra().readInt16LE(9) > 0;
    var compressionStream = deflate ? new DeflateCRC32Stream(this.options.zlib) : new CRC32Stream();
    var encryptionStream = new AesHmacEtmStream({key: ae.encryptKey, salt: this.options.salt});
    var error = null;

    function onEnd() {
        var digest = compressionStream.digest().readUInt32BE(0);
        ae.setCrc(digest);
        ae.setSize(compressionStream.size());
        ae.setCompressedSize(encryptionStream.getTotalSize());
        this._afterAppend(ae);
        callback(error, ae);
    }

    encryptionStream.once('end', onEnd.bind(this));
    compressionStream.once('error', function (err) {
        error = err;
    });

    compressionStream.pipe(encryptionStream).pipe(this, {end: false});

    return compressionStream;
};

ZipAesStream.prototype.setEntryKey = function setEntryKey(entry, key) {
    if (key === false || key === '') {
        entry.encryptKey = false;
    } else if (!Buffer.isBuffer(key)) {
        entry.encryptKey = Buffer.from(key, 'utf-8');
    } else {
        entry.encryptKey = key;
    }
};

ZipAesStream.prototype.entry = function(source, data, callback) {
    if (typeof callback !== 'function') {
        callback = this._emitErrorCallback.bind(this);
    }

    data = this._normalizeFileData(data);

    if (data.type !== 'file' && data.type !== 'directory' && data.type !== 'symlink') {
        callback(new Error(data.type + ' entries not currently supported'));
        return;
    }

    if (typeof data.name !== 'string' || data.name.length === 0) {
        callback(new Error('entry name must be a non-empty string value'));
        return;
    }

    if (data.type === 'symlink' && typeof data.linkname !== 'string') {
        callback(new Error('entry linkname must be a non-empty string value when type equals symlink'));
        return;
    }

    var entry = new ZipArchiveEntry(data.name);
    entry.setTime(data.date, this.options.forceLocalTime);

    if (data.store) {
        entry.setMethod(0);
    }

    if (data.comment.length > 0) {
        entry.setComment(data.comment);
    }

    if (data.type === 'symlink' && typeof data.mode !== 'number') {
        data.mode = 40960; // 0120000
    }

    if (typeof data.mode === 'number') {
        if (data.type === 'symlink') {
            data.mode |= 40960;
        }

        entry.setUnixMode(data.mode);
    }

    if (data.type === 'symlink' && typeof data.linkname === 'string') {
        source = Buffer.from(data.linkname);
    }

    if (data.password === undefined || data.password === null) {
        this.setEntryKey(entry, this.key);
    } else {
        this.setEntryKey(entry, data.password);
    }

    return ZipArchiveOutputStream.prototype.entry.call(this, entry, source, callback);
};

module.exports = ZipAesStream;