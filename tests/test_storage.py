"""pruebas unitarias de la máquina de estados de metadatos (sin cluster)"""
import subprocess
import sys
import textwrap
from pathlib import Path

CONTROL = Path(__file__).resolve().parents[1] / "control_node"


def run_storage(code: str) -> subprocess.CompletedProcess:
    """cada prueba corre en un proceso nuevo porque storage guarda el estado en memoria a nivel de módulo"""
    return subprocess.run([sys.executable, "-c", "import storage\nstorage.init_db()\n" + textwrap.dedent(code)],
                          cwd=CONTROL, capture_output=True, text=True)


def ok(r):
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def test_register_user_creates_home_atomically():
    out = ok(run_storage("""
        assert storage.register_user('ana', 'h1') == 'ok'
        assert storage.register_user('ana', 'h2') == 'exists'
        assert storage.get_user_hash('ana') == 'h1'
        assert storage.get_dir_owner('/ana') == 'ana'
        storage.add_dir('/docs', 'ana')
        assert storage.register_user('docs', 'h3') == 'name_taken'     # el nombre choca con un directorio
        assert storage.get_user_hash('docs') is None
        print('ok')
    """))
    assert "ok" in out


def test_snapshot_dump_and_load_restore_full_state():
    """es lo que usa raft para compactar el log y poner al día a un nodo nuevo"""
    out = ok(run_storage("""
        storage.register_user('ana', 'h')
        storage.create_empty_file('/ana/f', 'ana', 4096, 1.0)
        h = storage.open_handle('h1', '/ana/f', 'ana', True, 2.0)
        assert storage.acquire_lock('/ana/f', 'h1', 'exclusive')
        snap = storage.dump()
        storage.init_db()                                   # estado vacío
        assert storage.get_file('/ana/f') is None and not storage.is_locked('/ana/f')
        storage.load(snap)
        assert storage.get_file('/ana/f')['version'] == 1
        assert storage.get_handle('h1')['path'] == '/ana/f'
        assert storage.locks_for('/ana/f') == [{'handle': 'h1', 'mode': 'exclusive'}]
        assert storage.get_user_hash('ana') == 'h'
        storage.add_dir('/despues', 'ana')                   # y sigue siendo escribible
        print('ok')
    """))
    assert "ok" in out


def test_every_mutation_is_registered_as_an_op_and_deterministic():
    """dos nodos que aplican las mismas operaciones en el mismo orden terminan con el mismo estado"""
    out = ok(run_storage("""
        import json
        def play():
            storage.init_db()
            storage.OPS['register_user'](username='ana', password_hash='h')
            storage.OPS['create_empty_file'](path='/ana/f', owner='ana', block_size=4096, now=5.0)
            storage.OPS['open_handle'](handle_id='h1', path='/ana/f', owner='ana', writable=True, now=6.0)
            blk = [{'block_id': 'b' * 32, 'index': 0, 'size': 3, 'nodes': ['n1', 'n2'], 'checksum': '0' * 64}]
            storage.OPS['commit_handle'](handle_id='h1', size=3, blocks=blk, now=7.0)
            storage.OPS['update_block_nodes'](path='/ana/f', block_id='b' * 32, add='n3')
            return json.dumps(storage.get_file('/ana/f'), sort_keys=True), json.dumps(storage.get_handle('h1'), sort_keys=True)
        a = play(); b = play()
        assert a == b
        assert json.loads(a[0])['version'] == 2 and json.loads(a[0])['created_at'] == 7.0
        assert json.loads(a[0])['blocks'][0]['nodes'] == ['n1', 'n2', 'n3']
        expected = {'register_user', 'add_dir', 'remove_dir', 'create_empty_file', 'delete_file', 'update_block_nodes',
                    'create_upload', 'refresh_upload', 'delete_upload', 'commit_upload', 'acquire_lock', 'release_lock', 'open_handle',
                    'delete_handle', 'add_allocated', 'commit_handle', 'refresh_handle', 'noop',
                    'set_password', 'bump_epoch', 'totp_setup', 'totp_enable', 'totp_disable', 'create_group',
                    'delete_group', 'group_member', 'set_acl', 'create_apikey', 'delete_apikey',
                    'drop_replica', 'drop_missing_replicas', 'rename_path'}
        assert set(storage.OPS) == expected, set(storage.OPS) ^ expected
        print('ok')
    """))
    assert "ok" in out


def test_lock_rules_and_commit_guards():
    out = ok(run_storage("""
        assert storage.create_empty_file('/f', 'u', 4096, 1.0)
        assert not storage.create_empty_file('/f', 'u', 4096, 1.0)
        storage.open_handle('h1', '/f', 'u', True, 2.0); storage.open_handle('h2', '/f', 'u', True, 2.0)
        assert storage.acquire_lock('/f', 'h1', 'shared') and storage.acquire_lock('/f', 'h2', 'shared')
        assert not storage.acquire_lock('/f', 'h1', 'exclusive')          # h2 comparte
        storage.release_lock('/f', 'h2')
        assert storage.acquire_lock('/f', 'h1', 'exclusive')
        assert not storage.acquire_lock('/f', 'h2', 'shared')
        for call in (lambda: storage.commit_handle('h2', 0, [], 3.0), lambda: storage.delete_file('/f')):
            try:
                call(); raise SystemExit('debió fallar por lock')
            except storage.Locked:
                pass
        storage.delete_handle('h1')                                        # suelta sus locks
        assert not storage.is_locked('/f')
        old, alloc, h = storage.commit_handle('h2', 0, [], 3.0)
        assert h['base_version'] == 2
        storage.open_handle('h3', '/f', 'u', True, 4.0)
        storage.commit_handle('h3', 0, [], 5.0)                            # v3
        try:
            storage.commit_handle('h2', 0, [], 6.0)                        # h2 sigue en v2 -> conflicto
            raise SystemExit('debió ser conflicto')
        except storage.Conflict:
            pass
        try:
            storage.commit_handle('nope', 0, [], 7.0)
            raise SystemExit('debió ser Gone')
        except storage.Gone:
            pass
        print('ok')
    """))
    assert "ok" in out


def test_rename_moves_whole_trees_with_their_acl_sessions_and_listings():
    out = ok(run_storage("""
        storage.register_user('ana', 'h')
        for d in ('/ana/a', '/ana/a/b', '/ana/otro'):
            storage.add_dir(d, 'ana')
        storage.create_empty_file('/ana/a/b/f', 'ana', 4096, 1.0)
        storage.create_empty_file('/ana/suelto', 'ana', 4096, 1.0)
        storage.set_acl('/ana/a', 'user:bob', 'rw')
        storage.set_acl('/ana/a/b/f', 'user:eve', 'r')
        storage.open_handle('h1', '/ana/a/b/f', 'ana', True, 2.0)

        assert storage.rename_path('/ana/a', '/ana/z') == 'ok'
        assert storage.get_file('/ana/z/b/f') is not None and storage.get_file('/ana/a/b/f') is None
        assert storage.get_dir_owner('/ana/z/b') == 'ana' and storage.get_dir_owner('/ana/a') is None
        assert storage.acl_for('/ana/z') == [{'principal': 'user:bob', 'perm': 'rw'}]
        assert storage.acl_for('/ana/z/b/f') == [{'principal': 'user:eve', 'perm': 'r'}]
        assert storage.acl_for('/ana/a') == []
        assert storage.get_handle('h1')['path'] == '/ana/z/b/f'                      # la sesión sigue al archivo
        assert sorted(d['path'] for d in storage.child_dirs('/ana')) == ['/ana/otro', '/ana/z']
        assert [f['path'] for f in storage.child_files('/ana/z/b')] == ['/ana/z/b/f']

        assert storage.rename_path('/ana/suelto', '/ana/z/nuevo') == 'ok'            # un archivo suelto
        assert storage.get_file('/ana/z/nuevo') and storage.get_file('/ana/suelto') is None
        assert storage.rename_path('/ana/z', '/ana/z') == 'ok'                       # mismo nombre: nada que hacer
        assert storage.rename_path('/ana/nada', '/ana/x') == 'src_missing'
        assert storage.rename_path('/ana/z', '/ana/otro') == 'dst_exists'
        assert storage.rename_path('/ana/z', '/ana/z/b/dentro') == 'into_itself'
        assert storage.rename_path('/ana/z/nuevo', '/ana/no_existe/x') == 'dst_parent_missing'
        assert storage.rename_path('/ana/z/nuevo', '/ana/otro') == 'dst_exists'      # tampoco se pisa un directorio
        storage.acquire_lock('/ana/z/b/f', 'h1', 'exclusive')
        assert storage.rename_path('/ana/z', '/ana/w') == 'locked'                   # con un lock vivo dentro no se mueve
        assert storage.get_file('/ana/z/b/f') is not None
        # /ana/zeta no es "hijo" de /ana/z: el prefijo se compara con '/'
        storage.add_dir('/ana/zeta', 'ana')
        storage.release_lock('/ana/z/b/f', 'h1')
        assert storage.rename_path('/ana/z', '/ana/w') == 'ok' and storage.get_dir_owner('/ana/zeta') == 'ana'
        print('ok')
    """))
    assert "ok" in out


def test_deleted_handle_keeps_snapshot_but_cannot_mutate_recreated_file():
    """borrar y volver a crear no reconecta un handle viejo, aunque los dos archivos sean versión 1"""
    ok(run_storage("""
        storage.register_user('ana', 'h')
        old = [{'block_id': 'a' * 32, 'index': 0, 'size': 3,
                'nodes': ['n1', 'n2'], 'checksum': '0' * 64}]
        new = [{**old[0], 'block_id': 'b' * 32}]
        staged = [{**old[0], 'block_id': 'c' * 32}]
        storage.create_upload('u1', '/ana/f', 'ana', 3, 65536, old, 1.0)
        storage.commit_upload('u1', old, 2.0)
        storage.open_handle('old', '/ana/f', 'ana', True, 3.0)
        storage.add_allocated('old', staged)
        storage.delete_file('/ana/f')
        storage.create_upload('u2', '/ana/f', 'ana', 3, 65536, new, 4.0)
        storage.commit_upload('u2', new, 5.0)
        snap = storage.dump()
        storage.init_db()
        storage.load(snap)                   # la invalidación sobrevive a recuperación Raft
        assert storage.get_file('/ana/f')['version'] == 1
        assert storage.get_handle('old')['blocks'] == old
        assert storage.get_handle('old')['base_version'] == -1
        assert {'a' * 32, 'c' * 32} <= storage.handle_block_ids()
        for operation in (
            lambda: storage.commit_handle('old', 0, [], 6.0),
            lambda: storage.refresh_handle('old'),
            lambda: storage.add_allocated('old', []),
            lambda: storage.acquire_lock('/ana/f', 'old', 'exclusive'),
        ):
            try:
                operation()
                raise AssertionError('un handle borrado no puede mutar el archivo nuevo')
            except storage.Gone:
                pass
        assert storage.get_file('/ana/f')['blocks'] == new
        assert not storage.is_locked('/ana/f')
        storage.delete_handle('old')         # solo cerrar libera su snapshot para GC
        assert 'a' * 32 not in storage.all_block_ids()
        assert 'c' * 32 not in storage.all_block_ids()
        assert 'b' * 32 in storage.all_block_ids()
    """))


def test_upload_commit_and_renew_revalidate_namespace_atomically():
    ok(run_storage("""
        storage.register_user('ana', 'h')
        storage.create_upload('u', '/ana/d', 'ana', 0, 65536, [], 1.0)
        storage.add_dir('/ana/d', 'ana')     # se creó mientras el upload aún era invisible
        for operation in (lambda: storage.commit_upload('u', [], 2.0),
                          lambda: storage.refresh_upload('u', 2.0)):
            try:
                operation()
                raise AssertionError('no debe publicar ni renovar sobre un directorio')
            except storage.Conflict:
                pass
        assert storage.get_file('/ana/d') is None
        assert storage.get_dir_owner('/ana/d') == 'ana'
        assert storage.get_upload('u')['created_at'] == 1.0
        storage.delete_upload('u')
        storage.create_upload('u2', '/ana/d/f', 'ana', 0, 65536, [], 3.0)
        storage.remove_dir('/ana/d')
        try:
            storage.commit_upload('u2', [], 4.0)
            raise AssertionError('no puede aparecer un hijo con padre borrado')
        except storage.Gone:
            pass
        assert storage.get_file('/ana/d/f') is None
        assert storage.get_upload('u2') is not None     # abort/GC todavía puede limpiar sus bloques
    """))


def test_namespace_checks_cover_creation_and_concurrent_rmdir():
    ok(run_storage("""
        storage.register_user('ana', 'h')
        storage.add_dir('/ana/d', 'ana')
        assert not storage.has_children('/ana/d')     # observación HTTP anterior a la escritura Raft
        storage.add_dir('/ana/d/child', 'ana')
        try:
            storage.remove_dir('/ana/d')
            raise AssertionError('rmdir debe comprobar hijos dentro de la transacción')
        except storage.Conflict:
            pass
        assert storage.get_dir_owner('/ana/d/child') == 'ana'
        assert storage.get_dir_owner('/ana/d') == 'ana'
        storage.remove_dir('/ana/d/child')
        storage.remove_dir('/ana/d')
        for operation in (
            lambda: storage.add_dir('/ana/d/child', 'ana'),
            lambda: storage.create_empty_file('/ana/d/f', 'ana', 65536, 1.0),
            lambda: storage.create_upload('u', '/ana/d/f', 'ana', 0, 65536, [], 1.0),
        ):
            try:
                operation()
                raise AssertionError('crear requiere padre vigente')
            except storage.Gone:
                pass
        storage.create_empty_file('/ana/f', 'ana', 65536, 1.0)
        storage.set_acl('/ana/f', 'user:bob', 'r')
        storage.add_dir('/ana/d', 'ana')
        for operation in (
            lambda: storage.add_dir('/ana/f', 'ana'),
            lambda: storage.remove_dir('/ana/f'),
            lambda: storage.create_empty_file('/ana/d', 'ana', 65536, 1.0),
            lambda: storage.create_upload('u', '/ana/d', 'ana', 0, 65536, [], 1.0),
            lambda: storage.remove_dir('/'),
        ):
            try:
                operation()
                raise AssertionError('tipo incompatible o raíz')
            except storage.Conflict:
                pass
        assert storage.acl_for('/ana/f') == [{'principal': 'user:bob', 'perm': 'r'}]
        storage.create_empty_file('/ocupado', 'ana', 65536, 1.0)
        assert storage.register_user('ocupado', 'h') == 'name_taken'
        assert not storage.user_exists('ocupado')
    """))


def test_upload_renewal_wins_over_previously_planned_expiration():
    ok(run_storage("""
        storage.register_user('ana', 'h')
        storage.create_upload('u', '/ana/f', 'ana', 0, 65536, [], 10.0)
        assert storage.stale_uploads(11.0) == ['u']
        up = storage.refresh_upload('u', 20.0)
        assert up['created_at'] == 20.0
        assert storage.delete_upload('u', stale_before=11.0) is None
        assert storage.get_upload('u') is not None
        assert storage.refresh_upload('u', 15.0)['created_at'] == 20.0
        assert storage.stale_uploads(20.0) == []
        assert storage.delete_upload('u', stale_before=21.0) is not None
        assert storage.refresh_upload('u', 30.0) is None
    """))


def test_totp_setup_never_disables_an_enabled_factor():
    ok(run_storage("""
        storage.register_user('ana', 'h')
        storage.totp_setup('ana', 'old-secret')
        storage.totp_enable('ana')
        try:
            storage.totp_setup('ana', 'new-secret')
            raise AssertionError('setup no debe desactivar 2FA')
        except storage.Conflict:
            pass
        user = storage.get_user('ana')
        assert user['totp_enabled'] and user['totp_secret'] == 'old-secret'
        storage.totp_disable('ana')
        storage.totp_setup('ana', 'new-secret')
        user = storage.get_user('ana')
        assert not user['totp_enabled'] and user['totp_secret'] == 'new-secret'
    """))


def test_missing_replica_batch_updates_each_file_and_is_idempotent():
    ok(run_storage("""
        storage.register_user('ana', 'h')
        def block(letter, nodes, index=0):
            return {'block_id': letter * 32, 'index': index, 'size': 3,
                    'nodes': nodes, 'checksum': '0' * 64}
        first = [block('a', ['n1', 'n2']), block('b', ['n1', 'n3'], 1),
                 block('c', ['n2', 'n3'], 2), block('d', ['n1', 'n2'], 3)]
        second = [block('e', ['n1', 'n2'])]
        untouched = [block('f', ['n2', 'n3'])]
        for uid, blocks in [('first', first), ('second', second), ('untouched', untouched)]:
            storage.create_upload(uid, '/ana/' + uid, 'ana', len(blocks) * 3, 3, blocks, 1.0)
            storage.commit_upload(uid, blocks, 2.0)
        missing = ['a' * 32, 'b' * 32, 'c' * 32, 'e' * 32, 'f' * 32, '0' * 32, 'a' * 32]
        assert storage.drop_missing_replicas('n1', missing) == ['/ana/first', '/ana/second']
        assert [b['nodes'] for b in storage.get_file('/ana/first')['blocks']] == [
            ['n2'], ['n3'], ['n2', 'n3'], ['n1', 'n2']]
        assert storage.get_file('/ana/second')['blocks'][0]['nodes'] == ['n2']
        assert storage.get_file('/ana/untouched')['blocks'] == untouched
        before = storage.list_files()
        assert storage.drop_missing_replicas('n1', missing) == []
        assert storage.drop_missing_replicas('unknown', missing) == []
        assert storage.drop_missing_replicas('n1', []) == []
        assert storage.list_files() == before
        assert storage.get_file('/ana/first')['version'] == 1
        assert storage.drop_replica('d' * 32, 'n1') == ['/ana/first']  # API individual conserva contrato
    """))
