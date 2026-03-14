package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityCriteriaCpe;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityCriteriaNode;
import dev.notegridx.security.assetvulnmanager.domain.enums.CriteriaOperator;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityCriteriaCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityCriteriaNodeRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
public class CriteriaTreeLoader {

    private final VulnerabilityCriteriaNodeRepository nodeRepository;
    private final VulnerabilityCriteriaCpeRepository cpeRepository;

    public CriteriaTreeLoader(
            VulnerabilityCriteriaNodeRepository nodeRepository,
            VulnerabilityCriteriaCpeRepository cpeRepository
    ) {
        this.nodeRepository = nodeRepository;
        this.cpeRepository = cpeRepository;
    }

    public LoadedCriteriaTree load(Long vulnerabilityId) {
        if (vulnerabilityId == null) {
            return LoadedCriteriaTree.empty(null);
        }

        List<VulnerabilityCriteriaNode> nodes =
                nodeRepository.findByVulnerabilityIdOrderByRootGroupNoAscSortOrderAscIdAsc(vulnerabilityId);

        if (nodes == null || nodes.isEmpty()) {
            return LoadedCriteriaTree.empty(vulnerabilityId);
        }

        List<VulnerabilityCriteriaCpe> cpes =
                cpeRepository.findByVulnerabilityIdOrderByNodeIdAscIdAsc(vulnerabilityId);

        Map<Long, VulnerabilityCriteriaNode> nodeById = new HashMap<>();
        Map<Long, List<VulnerabilityCriteriaNode>> childrenByParentId = new HashMap<>();
        Map<Long, List<VulnerabilityCriteriaCpe>> cpesByNodeId = new HashMap<>();

        for (VulnerabilityCriteriaNode n : nodes) {
            nodeById.put(n.getId(), n);
        }

        for (VulnerabilityCriteriaNode n : nodes) {
            if (n.getParentId() != null) {
                childrenByParentId.computeIfAbsent(n.getParentId(), k -> new ArrayList<>()).add(n);
            }
        }

        if (cpes != null) {
            for (VulnerabilityCriteriaCpe cpe : cpes) {
                cpesByNodeId.computeIfAbsent(cpe.getNodeId(), k -> new ArrayList<>()).add(cpe);
            }
        }

        Comparator<VulnerabilityCriteriaNode> nodeOrder = Comparator
                .comparing(VulnerabilityCriteriaNode::getRootGroupNo, Comparator.nullsFirst(Integer::compareTo))
                .thenComparing(VulnerabilityCriteriaNode::getSortOrder, Comparator.nullsFirst(Integer::compareTo))
                .thenComparing(VulnerabilityCriteriaNode::getId, Comparator.nullsFirst(Long::compareTo));

        List<CriteriaExpr> roots = nodes.stream()
                .filter(Objects::nonNull)
                .filter(n -> n.getParentId() == null)
                .sorted(nodeOrder)
                .map(n -> buildExpr(n, childrenByParentId, cpesByNodeId, nodeOrder))
                .filter(Objects::nonNull)
                .toList();

        return new LoadedCriteriaTree(vulnerabilityId, roots);
    }

    private CriteriaExpr buildExpr(
            VulnerabilityCriteriaNode node,
            Map<Long, List<VulnerabilityCriteriaNode>> childrenByParentId,
            Map<Long, List<VulnerabilityCriteriaCpe>> cpesByNodeId,
            Comparator<VulnerabilityCriteriaNode> nodeOrder
    ) {
        if (node == null) {
            return null;
        }

        List<VulnerabilityCriteriaNode> childNodes = new ArrayList<>(
                childrenByParentId.getOrDefault(node.getId(), List.of())
        );
        childNodes.sort(nodeOrder);

        if (node.getNodeType() == dev.notegridx.security.assetvulnmanager.domain.enums.CriteriaNodeType.LEAF_GROUP) {
            List<CriteriaCpePredicate> predicates = cpesByNodeId.getOrDefault(node.getId(), List.of())
                    .stream()
                    .filter(Objects::nonNull)
                    .map(c -> new CriteriaCpePredicate(
                            c.getId(),
                            c.getCpeName(),
                            c.getCpeVendorId(),
                            c.getCpeProductId(),
                            c.getVendorNorm(),
                            c.getProductNorm(),
                            c.getCpePart(),
                            c.getTargetSw(),
                            c.getTargetHw(),
                            c.getVersionStartIncluding(),
                            c.getVersionStartExcluding(),
                            c.getVersionEndIncluding(),
                            c.getVersionEndExcluding(),
                            c.isMatchVulnerable()
                    ))
                    .toList();

            return new CriteriaLeafExpr(
                    node.getId(),
                    node.isNegate(),
                    predicates
            );
        }

        List<CriteriaExpr> children = childNodes.stream()
                .map(child -> buildExpr(child, childrenByParentId, cpesByNodeId, nodeOrder))
                .filter(Objects::nonNull)
                .toList();

        return new CriteriaOperatorExpr(
                node.getId(),
                node.isNegate(),
                node.getOperator(),
                children
        );
    }

    public record LoadedCriteriaTree(
            Long vulnerabilityId,
            List<CriteriaExpr> roots
    ) {
        public static LoadedCriteriaTree empty(Long vulnerabilityId) {
            return new LoadedCriteriaTree(vulnerabilityId, List.of());
        }

        public boolean hasRoots() {
            return roots != null && !roots.isEmpty();
        }
    }

    public sealed interface CriteriaExpr permits CriteriaOperatorExpr, CriteriaLeafExpr {
        Long nodeId();
        boolean negate();
    }

    public record CriteriaOperatorExpr(
            Long nodeId,
            boolean negate,
            CriteriaOperator operator,
            List<CriteriaExpr> children
    ) implements CriteriaExpr {
    }

    public record CriteriaLeafExpr(
            Long nodeId,
            boolean negate,
            List<CriteriaCpePredicate> predicates
    ) implements CriteriaExpr {
    }

    public record CriteriaCpePredicate(
            Long id,
            String cpeName,
            Long cpeVendorId,
            Long cpeProductId,
            String vendorNorm,
            String productNorm,
            String cpePart,
            String targetSw,
            String targetHw,
            String versionStartIncluding,
            String versionStartExcluding,
            String versionEndIncluding,
            String versionEndExcluding,
            boolean matchVulnerable
    ) {
    }
}