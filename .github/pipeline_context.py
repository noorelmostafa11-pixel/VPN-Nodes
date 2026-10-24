"""Public launcher metadata only: locate the trusted private source for recovery."""
import base64
import io
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile

PUBLIC = 'noorelmostafa11-pixel/VPN-Nodes'
PRIVATE = 'noorelmostafa11-pixel/VPN-Nodes-Private'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def github(path):
    request = urllib.request.Request('https://api.github.com/repos/' + PUBLIC + path,
                                    headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                                             'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def artifact_context(artifact_id):
    request = urllib.request.Request('https://api.github.com/repos/' + PUBLIC + '/actions/artifacts/' + str(artifact_id) + '/zip',
                                    headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN']})
    try:
        urllib.request.build_opener(NoRedirect()).open(request, timeout=30)
        raise ValueError('Expected a signed artifact download redirect')
    except urllib.error.HTTPError as error:
        if error.code not in (301, 302, 303, 307):
            raise
        location = error.headers['Location']
    parsed = urllib.parse.urlparse(location)
    if (parsed.scheme != 'https' or parsed.username or not parsed.hostname
            or not parsed.hostname.endswith(('.blob.core.windows.net', '.actions.githubusercontent.com', '.githubusercontent.com'))):
        raise ValueError('Untrusted artifact storage host')
    # Never forward the GitHub bearer token to the signed storage URL.
    with urllib.request.urlopen(location, timeout=30) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('Context artifact is too large')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) != 1 or entries[0].filename != 'context.json' or entries[0].file_size > 8192:
            raise ValueError('Unexpected context artifact')
        return json.loads(archive.read(entries[0]))


def resolve():
    if os.environ.get('GITHUB_REPOSITORY') != PUBLIC:
        raise ValueError('This launcher belongs to the owned repository')
    source = os.environ.get('SOURCE_RUN_ID', '')
    current = os.environ['GITHUB_RUN_ID']
    if not source:
        revision = os.environ['EXPECTED_PIPELINE_REVISION']
        if not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise ValueError('Missing pinned private pipeline revision')
        return {'pipeline_revision': revision, 'source_pipeline_revision': revision,
                'source_run_id': current, 'legacy_source': '0'}
    if not re.fullmatch(r'[1-9][0-9]*', source) or source == current:
        raise ValueError('Invalid source run')
    run = github('/actions/runs/' + source)
    if (run.get('status') != 'completed' or run.get('conclusion') not in ('success', 'failure')
            or run.get('head_branch') != 'main' or run.get('path') != '.github/workflows/update.yml'
            or (run.get('head_repository') or {}).get('full_name') != PUBLIC
            or not re.fullmatch(r'[0-9a-f]{40}', run.get('head_sha', ''))):
        raise ValueError('Source must be an owned completed catalog run')
    artifacts = github('/actions/runs/' + source + '/artifacts?per_page=100')['artifacts']
    contexts = [a for a in artifacts if a['name'] == 'pipeline-context' and not a['expired']]
    if contexts:
        if len(contexts) != 1:
            raise ValueError('Ambiguous private source context')
        data = artifact_context(int(contexts[0]['id']))
        revision = data.get('pipeline_revision', '')
        if (data.get('schema') != 'vpn-private-pipeline-v1' or data.get('repository') != PUBLIC
                or data.get('private_repository') != PRIVATE or str(data.get('run_id')) != source
                or data.get('runner_revision') != run['head_sha']
                or not re.fullmatch(r'[0-9a-f]{40}', revision)):
            raise ValueError('Private source context failed provenance checks')
        return {'pipeline_revision': revision, 'source_pipeline_revision': revision,
                'source_run_id': source, 'legacy_source': '0'}
    workflow = github('/contents/.github/workflows/update.yml?ref=' + run['head_sha'])
    text = base64.b64decode(workflow['content']).decode()
    if ('Compile production nodecheck and record source and binary identity' not in text
            or 'VPN_NODES_PRIVATE_READ_KEY' in text or PRIVATE in text):
        raise ValueError('Private run is missing its pinned source context')
    return {'pipeline_revision': 'main', 'source_pipeline_revision': run['head_sha'],
            'source_run_id': source, 'legacy_source': '1'}


if __name__ == '__main__':
    values = resolve()
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        for name, value in values.items():
            output.write(name + '=' + value + '\n')
    print('Private pipeline source context validated')
